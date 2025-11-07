import os
import base64
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

# --- Load .env when running locally ---
if os.path.exists(".env"):
    load_dotenv()
    print("📦 Loaded .env file for local run")
else:
    print("🚀 Running in Render environment (no .env file)")

# --- Load SAML Config from Environment ---
SAML_SP_ENTITY_ID = os.getenv("SAML_SP_ENTITY_ID")
SAML_SP_ASSERTION_CONSUMER_URL = os.getenv("SAML_SP_ASSERTION_CONSUMER_URL")
SAML_IDP_ENTITY_ID = os.getenv("SAML_IDP_ENTITY_ID")
SAML_IDP_SSO_URL = os.getenv("SAML_IDP_SSO_URL")
SAML_IDP_CERT = (os.getenv("SAML_IDP_CERT") or "").replace("\\n", "\n").strip()

# --- Log Config Summary ---
print("-------- SAML CONFIGURATION --------")
print(f"SAML_SP_ENTITY_ID: {SAML_SP_ENTITY_ID}")
print(f"SAML_SP_ASSERTION_CONSUMER_URL: {SAML_SP_ASSERTION_CONSUMER_URL}")
print(f"SAML_IDP_ENTITY_ID: {SAML_IDP_ENTITY_ID}")
print(f"SAML_IDP_SSO_URL: {SAML_IDP_SSO_URL}")
print(f"SAML_IDP_CERT: {'[SET]' if SAML_IDP_CERT else '[NOT SET]'}")
print("------------------------------------")

# --- Initialize FastAPI ---
app = FastAPI(title="Simple SAML Service Provider")

# --- Prepare FastAPI Request for python3-saml ---
def prepare_request(request: Request, post_data: dict = None):
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", request.url.hostname),
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }

# --- Build SAML Settings Dynamically ---
def build_saml_settings():
    return {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": SAML_SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": SAML_SP_ASSERTION_CONSUMER_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
        },
        "idp": {
            "entityId": SAML_IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": SAML_IDP_SSO_URL,
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

# --- Home Page ---
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <h1>SAML Authentication Test</h1>
    <p>Click below to log in using your SAML provider.</p>
    <a href="/login"><button>Login with SAML</button></a><br><br>
    <a href="/metadata">Download SP Metadata</a>
    """

# --- SAML Login ---
@app.get("/login")
async def saml_login(request: Request):
    auth = OneLogin_Saml2_Auth(prepare_request(request), old_settings=build_saml_settings())
    redirect_url = auth.login()
    print(f"🔁 Redirecting user to IdP: {redirect_url}")
    return RedirectResponse(redirect_url)

# --- Assertion Consumer Service (ACS) ---
@app.post("/acs")
async def saml_acs(request: Request):
    form = await request.form()
    if "SAMLResponse" not in form:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse in form data")

    auth = OneLogin_Saml2_Auth(prepare_request(request, dict(form)), old_settings=build_saml_settings())
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        print("❌ SAML Errors:", errors)
        raise HTTPException(status_code=400, detail=f"SAML processing failed: {errors}")

    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    email = auth.get_nameid() or "unknown"
    print(f"✅ Authenticated via SAML: {email}")

    # Generate example internal tokens (for testing only)
    fake_access_token = base64.b64encode(f"{email}:access".encode()).decode()
    fake_refresh_token = base64.b64encode(f"{email}:refresh".encode()).decode()

    return JSONResponse({
        "message": "SAML authentication successful",
        "email": email,
        "access_token": fake_access_token,
        "refresh_token": fake_refresh_token,
        "token_type": "bearer",
    })

# --- Metadata Endpoint ---
@app.get("/metadata", response_class=HTMLResponse)
async def saml_metadata():
    saml_settings = OneLogin_Saml2_Settings(build_saml_settings(), sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if len(errors) > 0:
        return HTMLResponse(f"<h2>Invalid metadata:</h2><pre>{errors}</pre>", status_code=500)
    return HTMLResponse(content=metadata, media_type="application/xml")

# --- Optional Health Check ---
@app.get("/health")
async def health():
    return {"status": "ok", "sp_entity": SAML_SP_ENTITY_ID, "idp_entity": SAML_IDP_ENTITY_ID}

# --- Run Server Locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
