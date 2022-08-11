module Keycloak
  def self.find_public_key(auth_server_url, realm_id)
    url = "#{auth_server_url}/realms/#{realm_id}"

    RestClient.get(url) do |response, _request, _result|
      return Keycloak.rescue_response(response) if response.code == 200

      return nil
    end
  end
end
