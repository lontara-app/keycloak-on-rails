# frozen_string_literal: true

require 'keycloak/version'
require 'rest-client'
require 'json'
require 'jwt'
require 'base64'
require 'uri'

def isempty?(value)
  value.respond_to?(:empty?) ? !!value.empty? : !value
end

module Keycloak
  OLD_KEYCLOAK_JSON_FILE = 'keycloak.json'
  KEYCLOAK_JSON_FILE = 'config/keycloak.json'

  class << self
    attr_accessor :proxy, :generate_request_exception, :keycloak_controller,
                  :proc_cookie_token, :proc_external_attributes,
                  :realm, :auth_server_url, :secret, :resource, :public_key, :access_type
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

  module Client
    class << self
      attr_accessor :realm, :auth_server_url
      attr_reader :client_id, :secret, :configuration, :public_key, :access_type
    end

    def self.get_token(user, password, client_id = '', secret = '')
      setup_module

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'username' => user,
                  'password' => password,
                  'grant_type' => 'password' }

      mount_request_token(payload)
    end

    def self.get_token_by_code(code, redirect_uri, client_id = '', secret = '', client_session_state = '', client_session_host = '')
      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

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

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      token_endpoint = @configuration['token_endpoint'] if isempty?(token_endpoint)

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

      userinfo_endpoint = @configuration['userinfo_endpoint'] if isempty?(userinfo_endpoint)

      access_token = token['access_token'] if access_token.empty?
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

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      refresh_token = token['refresh_token'] if refresh_token.empty?

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

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'grant_type' => 'client_credentials' }

      mount_request_token(payload)
    end

    def self.get_token_introspection(token = '', client_id = '', secret = '', introspection_endpoint = '')
      if Keycloak.access_type == 'public'
        raise Keycloak::MethodNotSupported.new('Method not allowed for Public Access Type', :not_supported)
      end

      verify_setup

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      token = self.token['access_token'] if isempty?(token)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)

      payload = { 'token' => token }

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

      client_id = @client_id if isempty?(client_id)
      authorization_endpoint = @configuration['authorization_endpoint'] if isempty?(authorization_endpoint)

      p = URI.encode_www_form(response_type: response_type, client_id: client_id, redirect_uri: redirect_uri)
      "#{authorization_endpoint}?#{p}"
    end

    def self.logout(redirect_uri = '', refresh_token = '', client_id = '', secret = '', end_session_endpoint = '')
      verify_setup

      if token || !refresh_token.empty?

        refresh_token = JSON.parse(token)['refresh_token'] if refresh_token.empty?
        client_id = @client_id if isempty?(client_id)
        secret = @secret if isempty?(secret)
        end_session_endpoint = @configuration['end_session_endpoint'] if isempty?(end_session_endpoint)

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
      userinfo_endpoint = @configuration['userinfo_endpoint'] if isempty?(userinfo_endpoint)

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

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)
      access_token = JSON.parse(token)['access_token'] if access_token.empty?

      case Keycloak.access_type
      when 'confidential'
        # Logged in user always have token. So no need to check if token is any.
        if user_signed_in?(access_token, client_id, secret, introspection_endpoint)
          decoded_token = decoded_access_token(access_token)
          decoded_token.select { |t| t['resource_access'] }.first['resource_access']['account']['roles'].include?(user_role)
        end
      when 'public'
        decoded_token = decoded_access_token(access_token)
        decoded_token.select { |t| t['resource_access'] }.first['resource_access']['account']['roles'].include?(user_role)
      end
    end

    def self.user_signed_in?(access_token = '', client_id = '', secret = '', introspection_endpoint = '')
      # if Keycloak.access_type == 'public'
      #   raise Keycloak::MethodNotSupported.new('Method not allowed for Public Access Type', :not_supported)
      # end
      verify_setup

      return false if token.blank?

      client_id = @client_id if isempty?(client_id)
      secret = @secret if isempty?(secret)
      introspection_endpoint = @configuration['introspection_endpoint'] if isempty?(introspection_endpoint)
      access_token = JSON.parse(token)['access_token'] if access_token.empty?

      case Keycloak.access_type
      when 'public'
        !token_expired?(access_token)
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
      JWT.decode access_token, @public_key, true, { algorithm: 'RS256' }
    end

    def self.decoded_refresh_token(refresh_token = '')
      if token.blank? && refresh_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      refresh_token = JSON.parse(token)['refresh_token'] if refresh_token.empty?
      JWT.decode refresh_token, @public_key, true, { algorithm: 'RS256' }
    end

    KEYCLOACK_CONTROLLER_DEFAULT = 'session'

    def self.token_expired?(access_token = '')
      if token.blank? && access_token.blank?
        return JSON.parse({ message: 'User not logged in or Token not provided' }.to_json)
      end

      access_token = JSON.parse(token)['access_token'] if access_token.empty?
      decoded_token = decoded_access_token(access_token)

      decoded_token.select { |t| t['exp'] }.first['exp'] < Time.now.to_i
    end

    def self.get_installation
      if File.exist?(Keycloak.installation_file)
        installation = JSON File.read(Keycloak.installation_file)
        @realm = installation['realm']
        @client_id = installation['resource']
        @secret = installation['credentials']['secret']
        @public_key = installation['realm-public-key']
        @auth_server_url = installation['auth-server-url']
      else
        if isempty?(Keycloak.realm) || isempty?(Keycloak.auth_server_url)
          raise "#{Keycloak.installation_file} and realm settings not found."
        end

        @realm = Keycloak.realm
        @auth_server_url = Keycloak.auth_server_url
        @client_id = Keycloak.resource
        @secret = Keycloak.secret
        @public_key = Keycloak.public_key
      end
      openid_configuration
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

    def self.openid_configuration
      RestClient.proxy = Keycloak.proxy unless isempty?(Keycloak.proxy)
      config_url = "#{@auth_server_url}/realms/#{@realm}/.well-known/openid-configuration"
      request = lambda do
        RestClient.get config_url
      end
      response = exec_request request
      if response.code == 200
        @configuration = JSON response.body
      else
        response.return!
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
      @decoded_id_token = JWT.decode id_token, @public_key, true, { algorithm: 'RS256' } if id_token
    end
  end

  # Os recursos desse module (admin) serão utilizadas apenas por usuários que possuem as roles do client realm-management
  module Admin
    class << self
    end

    def self.get_users(query_parameters = nil, access_token = nil)
      generic_get('users/', query_parameters, access_token)
    end

    def self.get_users_by_group(id, query_parameters = nil, access_token = nil)
      generic_get("groups/#{id}/members", query_parameters, access_token)
    end

    def self.create_user(user_representation, access_token = nil)
      generic_post('users/', nil, user_representation, access_token)
    end

    def self.count_users(access_token = nil)
      generic_get('users/count/', nil, access_token)
    end

    def self.get_user(id, access_token = nil)
      generic_get("users/#{id}", nil, access_token)
    end

    def self.update_user(id, user_representation, access_token = nil)
      generic_put("users/#{id}", nil, user_representation, access_token)
    end

    def self.delete_user(id, access_token = nil)
      generic_delete("users/#{id}", nil, nil, access_token)
    end

    def self.revoke_consent_user(id, client_id = nil, access_token = nil)
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      generic_delete("users/#{id}/consents/#{client_id}", nil, nil, access_token)
    end

    def self.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      generic_put("users/#{id}/execute-actions-email", { redirect_uri: redirect_uri, client_id: client_id }, actions,
                  access_token)
    end

    def self.get_role_mappings(id, access_token = nil)
      generic_get("users/#{id}/role-mappings", nil, access_token)
    end

    def self.get_groups(query_parameters = nil, access_token = nil)
      generic_get('groups/', query_parameters, access_token)
    end

    def self.get_users_by_role_name(role_name, query_parameters = nil, access_token = nil)
      generic_get("roles/#{role_name}/users", query_parameters, access_token)
    end

    def self.get_groups_by_role_name(role_name, query_parameters = nil, access_token = nil)
      generic_get("roles/#{role_name}/groups", query_parameters, access_token)
    end

    def self.get_clients(query_parameters = nil, access_token = nil)
      generic_get('clients/', query_parameters, access_token)
    end

    def self.get_all_roles_client(id, access_token = nil)
      generic_get("clients/#{id}/roles", nil, access_token)
    end

    def self.get_roles_client_by_name(id, role_name, access_token = nil)
      generic_get("clients/#{id}/roles/#{role_name}", nil, access_token)
    end

    def self.get_users_client_by_role_name(id, role_name, access_token = nil)
      generic_get("clients/#{id}/roles/#{role_name}/users", nil, access_token)
    end

    def self.add_client_level_roles_to_user(id, client, role_representation, access_token = nil)
      generic_post("users/#{id}/role-mappings/clients/#{client}", nil, role_representation, access_token)
    end

    def self.delete_client_level_roles_from_user(id, client, role_representation, access_token = nil)
      generic_delete("users/#{id}/role-mappings/clients/#{client}", nil, role_representation, access_token)
    end

    def self.get_client_level_role_for_user_and_app(id, client, access_token = nil)
      generic_get("users/#{id}/role-mappings/clients/#{client}", nil, access_token)
    end

    def self.update_effective_user_roles(id, client_id, roles_names, access_token = nil)
      client = JSON get_clients({ clientId: client_id }, access_token)

      user_roles = JSON get_client_level_role_for_user_and_app(id, client[0]['id'], access_token)

      roles = []
      # Include new role
      roles_names.each do |r|
        next unless r && !r.empty?

        found = false
        user_roles.each do |ur|
          found = ur['name'] == r
          break if found

          found = false
        end
        unless found
          role = JSON get_roles_client_by_name(client[0]['id'], r, access_token)
          roles.push(role)
        end
      end

      garbage_roles = []
      # Exclude old role
      user_roles.each do |ur|
        found = false
        roles_names.each do |r|
          next unless r && !r.empty?

          found = ur['name'] == r
          break if found

          found = false
        end
        garbage_roles.push(ur) unless found
      end

      delete_client_level_roles_from_user(id, client[0]['id'], garbage_roles, access_token) if garbage_roles.count > 0

      add_client_level_roles_to_user(id, client[0]['id'], roles, access_token) if roles.count > 0
    end

    def self.reset_password(id, credential_representation, access_token = nil)
      generic_put("users/#{id}/reset-password", nil, credential_representation, access_token)
    end

    def self.get_effective_client_level_role_composite_user(id, client, access_token = nil)
      generic_get("users/#{id}/role-mappings/clients/#{client}/composite", nil, access_token)
    end

    # Generics methods

    def self.generic_get(service, query_parameters = nil, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, nil, 'GET')
    end

    def self.generic_post(service, query_parameters, body_parameter, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters,
                               body_parameter, 'POST')
    end

    def self.generic_put(service, query_parameters, body_parameter, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters,
                               body_parameter, 'PUT')
    end

    def self.generic_delete(service, query_parameters = nil, body_parameter = nil, access_token = nil)
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters,
                               body_parameter, 'DELETE')
    end

    def self.effective_access_token(access_token)
      if isempty?(access_token)
        Keycloak::Client.token['access_token']
      else
        access_token
      end
    end

    def self.base_url
      Keycloak::Client.auth_server_url + "/admin/realms/#{Keycloak::Client.realm}/"
    end

    def self.full_url(service)
      base_url + service
    end
  end

  module Internal
    include Keycloak::Admin

    class << self
    end

    def self.get_users(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        Keycloak::Admin.get_users(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.get_users_by_role_name(role_name, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_users_by_role_name(role_name, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.get_groups(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        Keycloak::Admin.get_groups(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.get_groups_by_role_name(role_name, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_groups_by_role_name(role_name, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.get_users_by_group(id, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_users_by_group(id, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.change_password(user_id, redirect_uri = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("users/#{user_id}/execute-actions-email"),
                                 { redirect_uri: redirect_uri, client_id: client_id },
                                 ['UPDATE_PASSWORD'],
                                 'PUT')
      }

      default_call(proc, client_id, secret)
    end

    def self.forgot_password(user_login, redirect_uri = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      user = get_user_info(user_login, true, client_id, secret)
      change_password(user['id'], redirect_uri, client_id, secret)
    end

    def self.get_logged_user_info(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        userinfo = JSON Keycloak::Client.get_userinfo
        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("users/#{userinfo['sub']}"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_user_info(user_login, whole_word = false, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        search = if user_login.index('@').nil?
                   { username: user_login }
                 else
                   { email: user_login }
                 end
        users = JSON Keycloak.generic_request(token['access_token'],
                                              Keycloak::Admin.full_url('users/'),
                                              search, nil, 'GET')
        users[0]
        if users.count.zero?
          raise Keycloak::UserLoginNotFound
        else
          efective_index = -1
          users.each_with_index do |user, i|
            if whole_word
              efective_index = i if user_login == user['username'] || user_login == user['email']
            else
              efective_index = 0
            end
            break if efective_index >= 0
          end

          if efective_index >= 0
            if whole_word
              users[efective_index]
            else
              users
            end
          else
            raise Keycloak::UserLoginNotFound
          end
        end
      }

      default_call(proc, client_id, secret)
    end

    def self.exists_name_or_email(value, user_id = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      begin
        usuario = Keycloak::Internal.get_user_info(value, true, client_id, secret)
        if user_id.empty? || user_id != usuario['id']
          !isempty?(usuario)
        else
          false
        end
      rescue StandardError
        false
      end
    end

    def self.logged_federation_user?(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)
      info = get_logged_user_info(client_id, secret)
      info['federationLink'] != nil
    end

    def self.create_simple_user(username, password, email, first_name, last_name, realm_roles_names, client_roles_names, proc = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      begin
        username.downcase!
        user = get_user_info(username, true, client_id, secret)
        new_user = false
      rescue Keycloak::UserLoginNotFound
        new_user = true
      rescue StandardError
        raise
      end

      proc_default = lambda { |token|
        user_representation = { username: username,
                                email: email,
                                firstName: first_name,
                                lastName: last_name,
                                enabled: true }

        if !new_user || Keycloak.generic_request(token['access_token'],
                                                 Keycloak::Admin.full_url('users/'),
                                                 nil, user_representation, 'POST')

          user = get_user_info(username, true, client_id, secret) if new_user

          credential_representation = { type: 'password',
                                        temporary: false,
                                        value: password }

          if !user['federationLink'].nil? || Keycloak.generic_request(token['access_token'],
                                                                      Keycloak::Admin.full_url("users/#{user['id']}/reset-password"),
                                                                      nil, credential_representation, 'PUT')

            client = JSON Keycloak.generic_request(token['access_token'],
                                                   Keycloak::Admin.full_url('clients/'),
                                                   { clientId: client_id }, nil, 'GET')

            if client_roles_names.count.positive?
              roles = []
              client_roles_names.each do |r|
                next if isempty?(r)

                role = JSON Keycloak.generic_request(token['access_token'],
                                                     Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles/#{r}"),
                                                     nil, nil, 'GET')
                roles.push(role)
              end

              if roles.count.positive?
                Keycloak.generic_request(token['access_token'],
                                         Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/clients/#{client[0]['id']}"),
                                         nil, roles, 'POST')
              end
            end

            if realm_roles_names.count.positive?
              roles = []
              realm_roles_names.each do |r|
                next if isempty?(r)

                role = JSON Keycloak.generic_request(token['access_token'],
                                                     Keycloak::Admin.full_url("roles/#{r}"),
                                                     nil, nil, 'GET')
                roles.push(role)
              end

              if roles.count.positive?
                Keycloak.generic_request(token['access_token'],
                                         Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/realm"),
                                         nil, roles, 'POST')
              end
            else
              true
            end
          end
        end
      }

      proc.call user if default_call(proc_default, client_id, secret) && !proc.nil?
    end

    def self.create_starter_user(username, password, email, client_roles_names, proc = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)
      Keycloak::Internal.create_simple_user(username, password, email, '', '', [], client_roles_names, proc, client_id,
                                            secret)
    end

    def self.get_client_roles(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token['access_token'])

        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_client_user_roles(user_id, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      proc = lambda { |token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token['access_token'])
        Keycloak::Admin.get_effective_client_level_role_composite_user(user_id, client[0]['id'], token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.has_role?(user_id, user_role, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      roles = JSON get_client_user_roles(user_id, client_id, secret)
      unless roles.nil?
        roles.each do |role|
          return true if role['name'].to_s == user_role.to_s
        end
      end

      false
    end

    def self.default_call(proc, client_id = '', secret = '')
      tk = nil
      resp = nil

      Keycloak::Client.get_installation

      client_id = Keycloak::Client.client_id if isempty?(client_id)
      secret = Keycloak::Client.secret if isempty?(secret)

      case Keycloak.access_type
      when 'public'
        payload = {
          'client_id' => client_id,
          'grant_type' => 'client_credentials'
        }
      when 'confidential'
        payload = {
          'client_id' => client_id,
          'client_secret' => secret,
          'grant_type' => 'client_credentials'
        }
      end

      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      request = lambda do
        RestClient.post(Keycloak::Client.configuration['token_endpoint'], payload,
                        header) do |response, _request, _result|
          case response.code
          when 200..399
            tk = JSON response.body
            resp = proc.call(tk)
          else
            response.return!
          end
        end
      end

      Keycloak::Client.exec_request request
    ensure
      if tk

        case Keycloak.access_type
        when 'public'
          payload = {
            'client_id' => client_id,
            'refresh_token' => tk['refresh_token']
          }
        when 'confidential'
          payload = {
            'client_id' => client_id,
            'client_secret' => secret,
            'refresh_token' => tk['refresh_token']
          }
        end

        header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
        request = lambda do
          RestClient.post(Keycloak::Client.configuration['end_session_endpoint'], payload,
                          header) do |response, _request, _result|
            case response.code
            when 200..399
              resp if resp.nil?
            else
              response.return!
            end
          end
        end
        Keycloak::Client.exec_request request
      end
    end
  end

  def self.generic_request(access_token, uri, query_parameters, body_parameter, method)
    Keycloak::Client.verify_setup
    final_url = uri

    header = { 'Content-Type' => 'application/x-www-form-urlencoded',
               'Authorization' => "Bearer #{access_token}" }

    if query_parameters
      parameters = URI.encode_www_form(query_parameters)
      final_url = final_url << '?' << parameters
    end

    case method.upcase
    when 'GET'
      request = lambda do
        RestClient.get(final_url, header) do |response, _request, _result|
          rescue_response(response)
        end
      end
    when 'POST', 'PUT'
      header['Content-Type'] = 'application/json'
      parameters = JSON.generate body_parameter
      request = lambda do
        case method.upcase
        when 'POST'
          RestClient.post(final_url, parameters, header) do |response, _request, _result|
            rescue_response(response)
          end
        else
          RestClient.put(final_url, parameters, header) do |response, _request, _result|
            rescue_response(response)
          end
        end
      end
    when 'DELETE'
      request = lambda do
        if body_parameter
          header['Content-Type'] = 'application/json'
          parameters = JSON.generate body_parameter
          RestClient::Request.execute(method: :delete, url: final_url,
                                      payload: parameters, headers: header) do |response, _request, _result|
            rescue_response(response)
          end
        else
          RestClient.delete(final_url, header) do |response, _request, _result|
            rescue_response(response)
          end
        end
      end
    else
      raise
    end

    request.call
  end

  def self.rescue_response(response)
    case response.code
    when 200..399
      if response.body.empty?
        true
      else
        response.body
      end
    when 400..499
      response.return!
    else
      if Keycloak.explode_exception
        response.return!
      else
        begin
          response.return!
        rescue RestClient::ExceptionWithResponse => e
          e.response
        rescue StandardError => e
          e.message
        end
      end
    end
  end
end

require 'keycloak/exceptions'
