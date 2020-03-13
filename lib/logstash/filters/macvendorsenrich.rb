# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "logstash/environment"
#require "logstash/patterns/core"
require "csv"

class LogStash::Filters::Macvendorsenrich < LogStash::Filters::Base
  # Custom filter that allows us to create a hash from a file specified in the path by the user.
  #
  # If the path is not specified, it will use the path determined by default.
  #
  # The loading of this file in memory allows to create a dynamic query to obtain the value of mac_vendor through the mac filtered in the event we are analyzing.

  config_name "macvendors"

  # Path allows you to indicate the path to the document that you want to load into memory for the creation of the hash.
  config :path, :validate => :path, :default => "/opt/rb/etc/objects/mac_vendors", :required => false
  
  public 
  def register
    @mac_vendors_hash = CSV.read(@path, quote_char: "\x00", headers: false, col_sep: "|" ).to_h
   end
  

  def filter(event)
    #coge del evento la client_mac y lo transforma para saber que mac_vendors le corresponde.
    if event.include?("client_mac") then
      # Transformamos el atributo a mayusculas para simplificar el match
      client_mac_normalize = event.get("client_mac").upcase
      #eliminacion de ":" del atrinbuto mac del mensaje
      client_mac_normalize.gsub!(":","")
      # Almacenamiento de los 6 primeros digitos del atributo mac
      client_mac_normalize = client_mac_normalize[0..5]
      #bucle for para recorrer el hash y hacer la comparacion
      @mac_vendors_hash.each do | key_mac, vendor_name |
        if client_mac_normalize == key_mac then
          event.set("client_mac_vendor" , vendor_name)
          break
        end
      end
    end
    yield event
    filter_matched(event)
  end # def filter
end  # class LogStash::Filters::Macvendor
