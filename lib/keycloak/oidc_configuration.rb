module Keycloak
  def self.openid_configuration
    RestClient.proxy = Keycloak.proxy unless empty?(Keycloak.proxy)
    config_url = "#{@auth_server_url}/realms/#{@realm}/.well-known/openid-configuration"
    request = lambda do
      RestClient.get config_url
    end
    response = Keycloak::Client.exec_request request
    if response.code == 200
      Keycloak.oidc_configuration = JSON response.body
    else
      response.return!
    end
  end
end
