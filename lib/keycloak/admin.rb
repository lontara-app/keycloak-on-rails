# frozen_string_literal: true

require_relative 'client'
require_relative 'generic_request'

module Keycloak
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
      client_id = Keycloak::Client.client_id if empty?(client_id)
      generic_delete("users/#{id}/consents/#{client_id}", nil, nil, access_token)
    end

    def self.update_account_email(id, actions, redirect_uri = '', client_id = nil, access_token = nil)
      client_id = Keycloak::Client.client_id if empty?(client_id)
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

      if garbage_roles.count > 0
        delete_client_level_roles_from_user(id, client[0]['id'], garbage_roles,
                                            access_token)
      end

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
      Keycloak.generic_request(effective_access_token(access_token), full_url(service), query_parameters, nil,
                               'GET')
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
      if empty?(access_token)
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
end
