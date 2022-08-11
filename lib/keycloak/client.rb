# frozen_string_literal: true

require_relative 'public_key'
require_relative 'oidc_configuration'
require_relative 'exceptions'

module Keycloak
  module Client
    class << self
      attr_accessor :realm, :auth_server_url
      attr_reader :client_id, :secret, :configuration, :access_type
    end

    def self.get_token(user, password, client_id = '', secret = '')
      setup_module

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'username' => user,
                  'password' => password,
                  'grant_type' => 'password' }

      mount_request_token(payload)
    end

    def self.public_key
      response = Keycloak.find_public_key(auth_server_url, realm)
  
      OpenSSL::PKey::RSA.new("-----BEGIN PUBLIC KEY-----\n #{response['public_key']} \n-----END PUBLIC KEY-----\n")
    end

    def self.get_token_by_code(code, redirect_uri, client_id = '', secret = '', client_session_state = '', client_session_host = '')
      verify_setup

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)

      case Keycloak.access_type
      when 'public'
        payload = {
          'client_id' => client_id,
          'code' => code,
          'grant_type' => 'authorization_code',
          'redirect_uri' => redirect_uri,
          'client_session_state' => client_session_state,
          'client_session_host' => client_session_host
        }
      when 'confidential'
        payload = {
          'client_id' => client_id,
          'client_secret' => secret,
          'code' => code,
          'grant_type' => 'authorization_code',
          'redirect_uri' => redirect_uri,
          'client_session_state' => client_session_state,
          'client_session_host' => client_session_host
        }
      end

      mount_request_token(payload)
    end

    def self.get_token_by_exchange(issuer, issuer_token, client_id = '', secret = '', token_endpoint = '')
      setup_module

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)
      token_endpoint = @configuration['token_endpoint'] if empty?(token_endpoint)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'audience' => client_id,
                  'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                  'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
                  'subject_issuer' => issuer,
                  'subject_token' => issuer_token }
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      request = lambda do
        RestClient.post(token_endpoint, payload, header) do |response, _request, _result|
          # case response.code
          # when 200
          # response.body
          # else
          # response.return!
          # end
          response.body
        end
      end
      exec_request request
    end

    def self.get_userinfo_issuer(access_token = '', userinfo_endpoint = '')
      verify_setup

      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      userinfo_endpoint = @configuration['userinfo_endpoint'] if empty?(userinfo_endpoint)

      access_token = JSON.parse(token)['access_token'] if access_token.empty?
      payload = { 'access_token' => access_token }
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      request = lambda do
        RestClient.post(userinfo_endpoint, payload, header) do |response, _request, _result|
          response.body
        end
      end

      exec_request request
    end

    def self.get_token_by_refresh_token(refresh_token = '', client_id = '', secret = '')
      verify_setup

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)
      refresh_token = JSON.parse(token)['refresh_token'] if refresh_token.empty?

      case Keycloak.access_type
      when 'public'
        payload = {
          'client_id' => client_id,
          'refresh_token' => refresh_token,
          'grant_type' => 'refresh_token'
        }
      when 'confidential'
        payload = {
          'client_id' => client_id,
          'client_secret' => secret,
          'refresh_token' => refresh_token,
          'grant_type' => 'refresh_token'
        }
      end

      mount_request_token(payload)
    end

    def self.get_token_by_client_credentials(client_id = '', secret = '')
      if Keycloak.access_type == 'public'
        raise Keycloak::MethodNotSupported.new('Method not allowed for Public Access Type', :not_supported)
      end

      setup_module

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'grant_type' => 'client_credentials' }

      mount_request_token(payload)
    end

    def self.get_token_introspection(access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      if Keycloak.access_type == 'public'
        raise Keycloak::MethodNotSupported.new('Method not allowed for Public Access Type', :not_supported)
      end

      verify_setup

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)
      access_token = JSON.parse(token)['access_token'] if empty?(access_token)
      introspection_endpoint = @configuration['introspection_endpoint'] if empty?(introspection_endpoint)

      payload = { 'token' => access_token }

      authorization = Base64.strict_encode64("#{client_id}:#{secret}")
      authorization = "Basic #{authorization}"

      header = { 'Content-Type' => 'application/x-www-form-urlencoded',
                 'authorization' => authorization }

      request = lambda do
        RestClient.post(introspection_endpoint, payload, header) do |response, _request, _result|
          case response.code
          when 200..399
            response.body
          else
            response.return!
          end
        end
      end

      exec_request request
    end

    def self.url_login_redirect(redirect_uri, response_type = 'code', client_id = '', authorization_endpoint = '')
      verify_setup

      client_id = @client_id if empty?(client_id)
      authorization_endpoint = @configuration['authorization_endpoint'] if empty?(authorization_endpoint)

      p = URI.encode_www_form(response_type: response_type, client_id: client_id, redirect_uri: redirect_uri)
      "#{authorization_endpoint}?#{p}"
    end

    def self.logout(redirect_uri = '', refresh_token = '', client_id = '', secret = '', end_session_endpoint = '')
      verify_setup

      if token || !refresh_token.empty?

        refresh_token = JSON.parse(token)['refresh_token'] if refresh_token.empty?
        client_id = @client_id if empty?(client_id)
        secret = @secret if empty?(secret)
        end_session_endpoint = @configuration['end_session_endpoint'] if empty?(end_session_endpoint)

        case Keycloak.access_type
        when 'public'
          payload = {
            'client_id' => client_id,
            'refresh_token' => refresh_token
          }

        when 'confidential'
          payload = {
            'client_id' => client_id,
            'client_secret' => secret,
            'refresh_token' => refresh_token
          }
        end

        header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

        final_url = if redirect_uri.empty?
                      end_session_endpoint
                    else
                      "#{end_session_endpoint}?#{URI.encode_www_form(redirect_uri: redirect_uri)}"
                    end

        request = lambda do
          RestClient.post(final_url, payload, header) do |response, _request, _result|
            case response.code
            when 200..399
              true
            else
              response.return!
            end
          end
        end

        exec_request request
      else
        true
      end
    end

    def self.get_userinfo(access_token = '', userinfo_endpoint = '')
      verify_setup

      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      access_token = JSON.parse(token)['access_token'] if access_token.empty?
      userinfo_endpoint = @configuration['userinfo_endpoint'] if empty?(userinfo_endpoint)

      payload = { 'access_token' => access_token }

      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      request = lambda do
        RestClient.post(userinfo_endpoint, payload, header) do |response, _request, _result|
          case response.code
          when 200
            response.body
          when 401
            JSON.parse({ message: 'Unauthorized', status: 401 }.to_json)
          else
            response.return!
          end
        end
      end

      exec_request request
    end

    def self.url_user_account
      verify_setup

      "#{@auth_server_url}/realms/#{@realm}/account"
    end

    def self.has_role?(user_role, access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if empty?(introspection_endpoint)
      access_token = JSON.parse(token)['access_token'] if access_token.empty?

      case Keycloak.access_type
      when 'confidential'
        # Logged in user always have token. So no need to check if token is any.
        if user_signed_in?(access_token, client_id, secret, introspection_endpoint)
          decoded_token = decoded_access_token(access_token)
          decoded_token.select do |t|
            t['resource_access']
          end.first['resource_access']['account']['roles'].include?(user_role)
        end
      when 'public'
        decoded_token = decoded_access_token(access_token)
        decoded_token.select do |t|
          t['resource_access']
        end.first['resource_access']['account']['roles'].include?(user_role)
      end
    end

    def self.user_signed_in?(access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      verify_setup

      return false if token.blank?

      client_id = @client_id if empty?(client_id)
      secret = @secret if empty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if empty?(introspection_endpoint)
      access_token = JSON.parse(token)['access_token'] if access_token.empty?

      case Keycloak.access_type
      when 'public'
        begin
          !token_expired?(access_token)
        rescue JWT::ExpiredSignature
          false
        end
      when 'confidential'
        begin
          JSON(get_token_introspection(access_token, client_id, secret, introspection_endpoint))['active'] == true
        rescue StandardError => e
          e.class < Keycloak::KeycloakException ? raise(e) : false
        end
      end
    end

    def self.get_attribute(attribute_name, access_token = '')
      verify_setup

      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      access_token = JSON.parse(token)['access_token'] if access_token.empty?

      decoded_token = decoded_access_token(access_token)
      { attribute_name => decoded_token.select { |t| t[attribute_name] }.first[attribute_name] }
    end

    def self.token
      raise Keycloak::ProcCookieTokenNotDefined if Keycloak.proc_cookie_token.nil?

      Keycloak.proc_cookie_token.call
    end

    def self.external_attributes
      raise Keycloak::ProcExternalAttributesNotDefined if Keycloak.proc_external_attributes.nil?

      Keycloak.proc_external_attributes.call
    end

    def self.decoded_access_token(access_token = '')
      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      access_token = JSON.parse(token)['access_token'] if access_token.empty?
      JWT.decode access_token, public_key, true, { algorithm: 'RS256' }
    end

    def self.decoded_refresh_token(refresh_token = '')
      if token.blank? && refresh_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      refresh_token = JSON.parse(token)['refresh_token'] if refresh_token.empty?
      JWT.decode refresh_token, '', false, { algorithm: 'HS256' }
    end

    KEYCLOACK_CONTROLLER_DEFAULT = 'session'

    def self.token_expired?(access_token = '')
      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      access_token = JSON.parse(token)['access_token'] if access_token.empty?
      decoded_token = decoded_access_token(access_token)

      begin
        decoded_token.select { |t| t['exp'] }.first['exp'] < Time.now.to_i
      rescue JWT::ExpiredSignature
        false
      end
    end

    def self.get_installation
      if File.exist?(Keycloak.installation_file)
        installation = JSON File.read(Keycloak.installation_file)
        @realm = installation['realm']
        @client_id = installation['resource']
        @secret = installation['credentials']['secret']
        @auth_server_url = installation['auth-server-url']
      else
        if empty?(Keycloak.realm) || empty?(Keycloak.auth_server_url)
          raise "#{Keycloak.installation_file} and realm settings not found."
        end

        @realm = Keycloak.realm
        @auth_server_url = Keycloak.auth_server_url
        @client_id = Keycloak.resource
        @secret = Keycloak.secret
      end

      Keycloak.openid_configuration
    end

    def self.verify_setup
      get_installation if @configuration.nil?
    end

    def self.setup_module
      Keycloak.proxy ||= ''
      Keycloak.keycloak_controller ||= KEYCLOACK_CONTROLLER_DEFAULT
      get_installation
    end

    def self.exec_request(proc_request)
      if Keycloak.explode_exception
        proc_request.call
      else
        begin
          proc_request.call
        rescue RestClient::ExceptionWithResponse => e
          e.response
        end
      end
    end

    def self.mount_request_token(payload)
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      request = lambda do
        RestClient.post(@configuration['token_endpoint'], payload, header) do |response, _request, _result|
          case response.code
          when 200
            response.body
          else
            response.return!
          end
        end
      end

      exec_request request
    end

    def self.decoded_id_token(id_token = '')
      tk = token
      id_token = tk['id_token'] if id_token.empty?
      @decoded_id_token = JWT.decode id_token, public_key, true, { algorithm: 'RS256' } if id_token
    end
  end
end
