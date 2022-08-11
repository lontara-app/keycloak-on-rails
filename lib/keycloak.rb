# frozen_string_literal: true

require_relative 'keycloak/admin'
require_relative 'keycloak/client'
require_relative 'keycloak/exceptions'
require_relative 'keycloak/generic_request'
require_relative 'keycloak/internal'
require_relative 'keycloak/oidc_configuration'
require_relative 'keycloak/public_key'
require_relative 'keycloak/rescue'
require_relative 'keycloak/version'
require_relative 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

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
