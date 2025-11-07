import os
from dotenv import load_dotenv
import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# Load .env when local
if os.path.exists(".env"):
    load_dotenv()
    print("📦 Loaded .env file for local run")
else:
    print("🚀 Running in Render environment (no .env)")

# Load env
SAML_ISSUER = os.getenv("SAML_ISSUER")
SAML_CALLBACK_URL = os.getenv("SAML_CALLBACK_URL")
SAML_ENTRY_POINT = os.getenv("SAML_ENTRY_POINT")
SAML_IDP_ENTITY_ID = os.getenv("SAML_IDP_ENTITY_ID")
SAML_IDP_CERT = os.getenv("SAML_IDP_CERT")

app = FastAPI(title="Simple SAML SP")

print("-------- SAML SP Configuration --------")
print(f"SAML_ISSUER: {SAML_ISSUER}")
print(f"SAML_CALLBACK_URL: {SAML_CALLBACK_URL}")
print(f"SAML_ENTRY_POINT: {SAML_ENTRY_POINT}")
print(f"SAML_IDP_ENTITY_ID: {SAML_IDP_ENTITY_ID}")
print(f"SAML_IDP_CERT: {'[SET]' if SAML_IDP_CERT else '[NOT SET]'}")
print("---------------------------------------")

# --- Helper: Prepare FastAPI request for python3-saml
def prepare_request(request: Request, post_data: dict = None):
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", request.url.hostname),
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


# --- Helper: Build dynamic SAML settings
def build_saml_settings():
    return {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": SAML_ISSUER,
            "assertionConsumerService": {
                "url": SAML_CALLBACK_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
        },
        "idp": {
            "entityId": SAML_IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": SAML_ENTRY_POINT,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": SAML_IDP_CERT,
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


# --- Home page
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <h1>SAML Authentication Test</h1>
    <p>Click below to log in using your SAML provider.</p>
    <a href="/login"><button>Login with SAML</button></a><br><br>
    <a href="/metadata">Download SP Metadata</a>
    """


# --- SAML Login
@app.get("/login")
async def saml_login(request: Request):
    auth = OneLogin_Saml2_Auth(prepare_request(request), old_settings=build_saml_settings())
    redirect_url = auth.login()
    print(f"Redirecting user to IdP: {redirect_url}")
    return RedirectResponse(redirect_url)


# --- SAML Assertion Consumer Service (ACS)
@app.post("/acs")
async def saml_acs(request: Request):
    form = await request.form()
    if "SAMLResponse" not in form:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse in form data")

    auth = OneLogin_Saml2_Auth(prepare_request(request, dict(form)), old_settings=build_saml_settings())
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        print("SAML Errors:", errors)
        raise HTTPException(status_code=400, detail=f"SAML processing failed: {errors}")

    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    email = auth.get_nameid() or "unknown"
    print(f"✅ Authenticated via SAML: {email}")

    # Sample internal token (for demonstration)
    fake_access_token = base64.b64encode(f"{email}:access".encode()).decode()
    fake_refresh_token = base64.b64encode(f"{email}:refresh".encode()).decode()

    return JSONResponse({
        "message": "SAML authentication successful",
        "email": email,
        "access_token": fake_access_token,
        "refresh_token": fake_refresh_token,
        "token_type": "bearer",
    })


# --- SP Metadata endpoint
@app.get("/metadata", response_class=HTMLResponse)
async def saml_metadata():
    saml_settings = OneLogin_Saml2_Settings(build_saml_settings(), sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if len(errors) > 0:
        return HTMLResponse(f"<h2>Invalid metadata:</h2><pre>{errors}</pre>", status_code=500)
    return HTMLResponse(content=metadata, media_type="application/xml")


# --- Run server locally
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
