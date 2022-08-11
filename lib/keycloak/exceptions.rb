module Keycloak
    class KeycloakException < StandardError; end
    class UserLoginNotFound < KeycloakException; end
    class ProcCookieTokenNotDefined < KeycloakException; end
    class ProcExternalAttributesNotDefined < KeycloakException; end
    class InstallationFileNotFound < KeycloakException; end
    class MethodNotSupported < KeycloakException
        def initialize(message = '', exception_type = '')
            @exception_type = exception_type
            super(message)
        end
    end
end