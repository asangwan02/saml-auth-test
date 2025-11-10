import os
from dotenv import load_dotenv

# --- Load .env before imports using it ---
if os.path.exists(".env"):
    load_dotenv()
    print("📦 Loaded .env file for local run")
else:
    print("🚀 Running in Render environment (no .env file)")

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from saml_auth_service import saml_auth_service

# --- Initialize FastAPI ---
app = FastAPI(title="Simple SAML Service Provider")

# --- Home Page ---
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <h1>SAML Authentication Test</h1>
    <p>Click below to log in using your SAML provider.</p>
    <a href="https://ciathena-dev.customerinsights.ai/auth/login/saml"><button>Login with SAML</button></a><br><br>
    """

# --- SAML Login ---
@app.get("/login")
async def saml_login(request: Request):
    redirect_url = saml_auth_service.initiate_login(request)
    return RedirectResponse(redirect_url)

# --- Assertion Consumer Service (ACS) ---
@app.post("/acs")
async def saml_assertion(request: Request):
    return await saml_auth_service.process_assertion(request)

@app.get("/health")
async def health():
    return {"status": "ok"}

# --- Run locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
