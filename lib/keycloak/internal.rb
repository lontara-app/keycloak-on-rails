# frozen_string_literal: true

require_relative 'admin'
require_relative 'client'
require_relative 'exceptions'
require_relative 'generic_request'

module Keycloak
  module Internal
    # include Keycloak::Admin

    class << self
    end

    def self.get_users(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda { |token|
        Keycloak::Admin.get_users(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.get_users_by_role_name(role_name, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_users_by_role_name(role_name, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.get_groups(query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda { |token|
        Keycloak::Admin.get_groups(query_parameters, token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.get_groups_by_role_name(role_name, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_groups_by_role_name(role_name, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.get_users_by_group(id, query_parameters = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda do |token|
        Keycloak::Admin.get_users_by_group(id, query_parameters, token['access_token'])
      end

      default_call(proc, client_id, secret)
    end

    def self.change_password(user_id, redirect_uri = '', client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

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
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      user = get_user_info(user_login, true, client_id, secret)
      change_password(user['id'], redirect_uri, client_id, secret)
    end

    def self.get_logged_user_info(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda { |token|
        userinfo = JSON Keycloak::Client.get_userinfo
        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("users/#{userinfo['sub']}"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_user_info(user_login, whole_word = false, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

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
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      begin
        usuario = Keycloak::Internal.get_user_info(value, true, client_id, secret)
        if user_id.empty? || user_id != usuario['id']
          !empty?(usuario)
        else
          false
        end
      rescue StandardError
        false
      end
    end

    def self.logged_federation_user?(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)
      info = get_logged_user_info(client_id, secret)
      info['federationLink'] != nil
    end

    def self.create_simple_user(username, password, email, first_name, last_name, realm_roles_names, client_roles_names, proc = nil, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

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
                next if empty?(r)

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
                next if empty?(r)

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
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)
      create_simple_user(username, password, email, '', '', [], client_roles_names, proc, client_id, secret)
    end

    def self.get_client_roles(client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda { |token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token['access_token'])

        Keycloak.generic_request(token['access_token'],
                                 Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles"),
                                 nil, nil, 'GET')
      }

      default_call(proc, client_id, secret)
    end

    def self.get_client_user_roles(user_id, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

      proc = lambda { |token|
        client = JSON Keycloak::Admin.get_clients({ clientId: client_id }, token['access_token'])
        Keycloak::Admin.get_effective_client_level_role_composite_user(user_id, client[0]['id'],
                                                                       token['access_token'])
      }

      default_call(proc, client_id, secret)
    end

    def self.has_role?(user_id, user_role, client_id = '', secret = '')
      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

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

      client_id = Keycloak::Client.client_id if empty?(client_id)
      secret = Keycloak::Client.secret if empty?(secret)

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
          RestClient.post(Keycloak::Client.configuration['end_session_endpoint'], payload, header) do |response, _request, _result|
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
end
