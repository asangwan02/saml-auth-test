import base64
import os

class TestService:
    def __init__(self):
        self.test_user_email = os.getenv("TEST_USER_EMAIL")

    def create_tokens(self, user_id: str, email: str, auth_type: str):
        fake_access_token = base64.b64encode(f"{user_id}:{email}:{auth_type}:access:".encode()).decode()
        fake_refresh_token = base64.b64encode(f"{user_id}:{email}:{auth_type}:refresh".encode()).decode()
    
        return {"access_token": fake_access_token, "refresh_token": fake_refresh_token}
    
    def get_auth_user(self, email: str):
        if email == self.test_user_email:
            return {"email": email, "id": "3f9c60a5-353e-49bf-83b5-85f2a6073a0d"}
        return None
    
# --- Singleton instance
test_service = TestService()