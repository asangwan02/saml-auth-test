import os
from fastapi import HTTPException, status, Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import base64
from test_service import test_service


class SamlAuthService:
    def __init__(self):
        self.sp_entity_id = os.getenv("SAML_SP_ENTITY_ID")
        self.acs_url = os.getenv("SAML_SP_ASSERTION_CONSUMER_URL")
        self.idp_entity_id = os.getenv("SAML_IDP_ENTITY_ID")
        self.idp_sso_url = os.getenv("SAML_IDP_SSO_URL")
        self.idp_cert = os.getenv("SAML_IDP_CERT")

    def _prepare_request(self, request: Request, post_data: dict = None):
        return {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.headers.get("host", request.url.hostname),
            "server_port": request.url.port
            or (443 if request.url.scheme == "https" else 80),
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": post_data or {},
        }

    def _build_saml_settings(self):
        return {
            "strict": True,
            "debug": True,
            "sp": {
                "entityId": self.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.idp_cert,
            },
            "security": {
                "authnRequestsSigned": False,
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "requestedAuthnContext": False,
                "signatureAlgorithm": "rsa-sha256",
                "digestAlgorithm": "sha256",
            },
            "nameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }

    def initiate_login(self, request: Request):
        
        print("-------- SAML CONFIGURATION --------")
        print(f"SAML_SP_ENTITY_ID: {self.sp_entity_id}")
        print(f"SAML_SP_ASSERTION_CONSUMER_URL: {self.acs_url}")
        print(f"SAML_IDP_ENTITY_ID: {self.idp_entity_id}")
        print(f"SAML_IDP_SSO_URL: {self.idp_sso_url}")
        print(f"SAML_IDP_CERT: {'[SET]' if self.idp_cert else '[NOT SET]'}")
        print("------------------------------------")

        req_data = self._prepare_request(request)
        settings = self._build_saml_settings()
        auth = OneLogin_Saml2_Auth(req_data, old_settings=settings)

        redirect_url = auth.login()
        print(f"Redirecting to IdP: {redirect_url}")
        return redirect_url

    async def process_assertion(self, request: Request):
        print("📥 [ACS] Received POST /acs (SAML Response)")

        form = await request.form()
        if "SAMLResponse" not in form:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing SAMLResponse in form data",
            )

        req_data = self._prepare_request(request, dict(form))
        settings = self._build_saml_settings()
        auth = OneLogin_Saml2_Auth(req_data, old_settings=settings)
        auth.process_response()
        errors = auth.get_errors()

        if errors:
            print("SAML Errors:", errors)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"SAML processing failed: {errors}",
            )

        if not auth.is_authenticated():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SAML authentication failed",
            )

        email = auth.get_nameid()
        print(f"User Email: {email}")
        user = test_service.get_auth_user(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        tokens = test_service.create_tokens(
            user_id=str(user["id"]), email=user["email"], auth_type="saml"
        )

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "bearer",
        }


# --- Singleton instance
saml_auth_service = SamlAuthService()
