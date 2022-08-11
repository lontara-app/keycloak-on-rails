module Keycloak
    class KeycloakException < StandardError; end
    class UserLoginNotFound < KeycloakException; end
    class ProcCookieTokenNotDefined < KeycloakException; end
    class ProcExternalAttributesNotDefined < KeycloakException; end
    class InstallationFileNotFound < KeycloakException; end
    class MethodNotSupported < KeycloakException; end
end