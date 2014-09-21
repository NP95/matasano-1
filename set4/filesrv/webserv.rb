#!/usr/bin/ruby
#
# Matasano Crypto Challenge #32
# simple server providing insecure SHA-1 HMAC validation

require 'base64'
require 'cgi'
require 'openssl'
require 'socket'
include Socket::Constants

def insecure_compare(params)
	hmac_correct = true
	i = params.index('filename%5D=')
	i = i + 12
	j = params.index('&', i)
	file = params.slice(i..j-1)

	i = params.index('signature%5D=')
	i = i + 13
	j = params.index('&', i)
	sig = params.slice(i..j-1)

	key = 'YELLOW SUBMARINE'

	digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), key, file)
	hex_digest = digest.unpack('H*')[0]

	start_time = Time.now()
	i=0
	until i==40 do
		if hex_digest[i] == sig[i] and hex_digest[i+1] == sig[i+1]
			i += 2
		else
			hmac_correct = false
			break
		end
		# 40 ms artificial delay
		#sleep(0.040)
		# 5 ms artificial delay (breaks basic timing attack approach
		sleep(0.005)
	end

	return hmac_correct
end

#server = TCPServer.new("localhost", 3000)
#loop do
#	Thread.start(server.accept) do |c|
Socket.tcp_server_loop(3000) do |c, cai|
	Thread.new {
	begin
		req = c.gets
		# perform check
		if insecure_compare(req) == true
			resp = "HTTP/1.1 +200 OK\r\nDate: Tue, 14 Dec 2010 10:48:45 GMT\r\nServer: Ruby\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n"
		else
			resp = "HTTP/1.1 +500 HMAC Failure!\r\nDate: Tue, 14 Dec 2010 10:48:45 GMT\r\nServer: Ruby\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n"
		end

		c.puts(resp)
	ensure
		c.close
	end
	}
end
