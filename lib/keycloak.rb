# frozen_string_literal: true

require 'keycloak/admin'
require 'keycloak/client'
require 'keycloak/exceptions'
require 'keycloak/generic_request'
require 'keycloak/internal'
require 'keycloak/oidc_configuration'
require 'keycloak/public_key'
require 'keycloak/rescue_response'
require 'keycloak/version'
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

def empty?(value)
  value.respond_to?(:empty?) ? !!value.empty? : !value
end

module Keycloak
  OLD_KEYCLOAK_JSON_FILE = 'keycloak.json'
  KEYCLOAK_JSON_FILE = 'config/keycloak.json'

  class << self
    attr_accessor :proxy, :generate_request_exception, :keycloak_controller,
                  :proc_cookie_token, :proc_external_attributes,
                  :realm, :auth_server_url, :secret, :resource, :access_type
  end

  def self.explode_exception
    Keycloak.generate_request_exception = true if Keycloak.generate_request_exception.nil?
    Keycloak.generate_request_exception
  end

  def self.installation_file
    @installation_file ||= if File.exist?(KEYCLOAK_JSON_FILE)
                             KEYCLOAK_JSON_FILE
                           else
                             OLD_KEYCLOAK_JSON_FILE
                           end
  end

  def self.installation_file=(file = nil)
    raise InstallationFileNotFound unless file.instance_of?(String) && File.exist?(file)

    @installation_file = file || KEYCLOAK_JSON_FILE
  end
end
