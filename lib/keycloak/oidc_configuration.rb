# frozen_string_literal: true

module Keycloak
  def self.openid_configuration
    RestClient.proxy = Keycloak.proxy unless empty?(Keycloak.proxy)
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
end
