# frozen_string_literal: true

module Keycloak
  module Rescue
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
end
