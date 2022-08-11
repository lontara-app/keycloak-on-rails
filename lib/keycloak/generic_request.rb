# frozen_string_literal: true

require_relative 'client'
require_relative 'rescue_response'

module Keycloak
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
end
