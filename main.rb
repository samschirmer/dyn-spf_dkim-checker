require 'rubygems'
require 'nokogiri'
require 'uri'
require 'resolv'
require 'tiny_tds'
require './secret'
include Secret

c = Secret::get
@client = TinyTds::Client.new username: c[:user], password: c[:pass], host: c[:host], database: c[:db]

def fetch_domains
	domains = Array.new
	result = @client.execute("select top 600 domain, spf, dkim, dmarc from bizops.dbo.tblemailauth where isnull(freeind, 0) = 0 and spf = 2")
	result.each(:symbolize_keys => true) do |row|
		domains.push(row)
	end
	return domains
end

def lookup_dkim(type, url)
	if type == 'key'
		url = "dyn._domainkey.#{url}"
	elsif type == 'policy'
		url = "_domainkey.#{url}"
	end
end

def lookup_spf(domains)
	has_other_spf = Array.new
	good_spf = Array.new
	bad_spf = Array.new
	counter = 0

	domains.each do |url|
		puts "#{domains.count - counter} to go..."
		counter += 1
		txts = Resolv::DNS.open do |dns|
		  records = dns.getresources(url, Resolv::DNS::Resource::IN::TXT)
		  records.empty? ? nil : records.map(&:data)
		end

		if txts.nil?
			bad_spf.push({url: url, note: 'No TXT records on domain'})
			next
		end
	
# capturing all non-Dyn SPF records (for duplicate detection)
		txts.each do |txt|
			if ((txt =~ /^v=spf1.*all$/) && (txt !~ /^v=spf1.*include:spf\.dynect\.net.*all$/))
				has_other_spf.push(url)
			end
		end

		valid = false
		txts.each do |txt|
			if txt =~ /^v=spf1.*include:spf\.dynect\.net.*all$/
				good_spf.push(url)
				valid = true
			else
				next
			end
		end
		unless valid
			bad_spf.push({url: url, note: 'No Dyn SPF record found'})
		end
	end
	# subtracting domains with multiple spfs from "good" array
	good_spf = good_spf - has_other_spf
	# adding duplicate spfs to "bad" array
	has_other_spf.each do |url|
		bad_spf.push({url: url, note: "Non-Dyn SPF record(s) on domain"})
	end
	puts "good: #{good_spf.count} | bad: #{bad_spf.count}"
	
	return good_spf, bad_spf
end

def record_result(valid, type, array)
	array.each do |record|
		if record.is_a? String
			sql = "UPDATE BizOps.dbo.tblEmailAuth SET #{type} = #{valid}, LastCheckDT = GETUTCDATE() WHERE Domain = '#{record}'"
		else
			sql = "UPDATE BizOps.dbo.tblEmailAuth SET #{type} = #{valid}, ProblemText = '#{record[:note]}', LastCheckDT = GETUTCDATE() WHERE Domain = '#{record[:url]}'"
		end	
		result = @client.execute(sql).do
	end
end

domains = fetch_domains
spf_todo = Array.new	
dkim_todo = Array.new	
dmarc_todo = Array.new	
domains.each do |d|
	if d[:spf] == 2
		spf_todo.push(d[:domain])
	end
	if d[:dkim] == 2
		dkim_todo.push(d[:domain])
	end
	if d[:dmarc] == 2
		dmarc_todo.push(d[:domain])
	end
end

puts "Need to look up #{spf_todo.count} spfs, #{dkim_todo.count} dkims, and #{dmarc_todo.count} dmarc records."
puts "Now processing SPF..."
good_spfs, bad_spfs = lookup_spf(spf_todo)
puts "Now writing to BizOps..."
record_result(1, 'SPF', good_spfs)
record_result(0, 'SPF', bad_spfs)

puts 'Done!'


