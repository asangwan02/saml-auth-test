import os
from dotenv import load_dotenv
from fastapi.responses import RedirectResponse

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
async def home(request: Request):
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    print("Access Token:", access_token)
    print("Refresh Token:", refresh_token)

    if access_token:
        return """
        <h1>Welcome Back!</h1>
        <p>You’re already logged in (access token found).</p>
        <a href="/logout"><button>Logout</button></a>
        """
    else:
        return """
        <h1>SAML Authentication Test</h1>
        <p>Click below to log in using your SAML provider.</p>
        <a href="/login"><button>Login with SAML</button></a><br><br>
        """

# --- Logout Route ---
@app.get("/logout")
async def logout():
    """
    Clears cookies and redirects to the home page.
    """
    response = RedirectResponse(url="/", status_code=303)

    # Clear both tokens
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    print("[Logout] Cleared cookies and redirected to home.")
    return response

# --- SAML Login ---
@app.get("/login")
async def saml_login(request: Request):
    redirect_url = saml_auth_service.initiate_login(request)
    return RedirectResponse(redirect_url)

# --- Assertion Consumer Service (ACS) ---
@app.post("/acs")
async def saml_assertion(request: Request):
    tokens = await saml_auth_service.process_assertion(request)

    redirect_url = "https://saml-auth-test.onrender.com/"
    response = RedirectResponse(url=redirect_url, status_code=303)

    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        secure=True,
        samesite="None",
        max_age=3600
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        secure=True,
        samesite="None",
        max_age=7 * 24 * 3600
    )
    return response

@app.get("/health")
async def health():
    return {"status": "ok"}

# --- Run locally ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
