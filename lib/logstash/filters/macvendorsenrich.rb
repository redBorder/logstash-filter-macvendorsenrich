# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "logstash/environment"
require "csv"

class LogStash::Filters::Macvendorsenrich < LogStash::Filters::Base

  config_name "macvendorsenrich"

  # Path allows you to indicate the path to the document that you want to load into memory for the creation of the hash.
  config :path, :validate => :path, :default => "/opt/rb/etc/objects/mac_vendors", :required => false

  public
  def register
    @mac_vendors_hash = CSV.read(@path, quote_char: "\x00", headers: false, col_sep: "|" ).to_h
  end


  def filter(event)
    if !event.include?("client_mac_vendor") and event.include?("client_mac")
      client_mac_normalize = (event.get("client_mac").to_s.upcase.gsub(":","").gsub("-",""))[0..5]

      if @mac_vendors_hash.key?(client_mac_normalize)
        vendor_name = @mac_vendors_hash[client_mac_normalize]
        event.set("client_mac_vendor" , vendor_name.to_s)
      end
    end
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Macvendor
