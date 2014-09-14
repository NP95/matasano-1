require 'base64'
require 'cgi'
require 'openssl'

class FilesController < ApplicationController
	def new
	end

	def index
		key = 'YELLOW SUBMARINE'
		signature = params[:file].fetch(:signature)
		filename = params[:file].fetch(:filename)

#		digest = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), key.encode("ASCII"), filename.encode("ASCII"))
		digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), key, filename)
		hex_digest = digest.unpack('H*')[0]

		start_time = Time.now()
		i=0
		hex_digest.each_char do |d|
			if d == signature[i]
				i += 1
			else
				break
			end
			sleep(0.040)
		end
		proc_time = Time.now() - start_time

		msg = "Request processed in #{proc_time} seconds.\r\n"
		if i==40
			msg += "+200\r\n\r\n"
		else
			msg += "+500\r\n\r\n"
		end

		debug = "#{signature}, #{filename}, #{hex_digest}, i=#{i}"

#		render plain: params[:file].inspect

		render plain: msg
	end
end
