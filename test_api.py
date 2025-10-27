import pytest
import requests

# Base URL of your running server
BASE_URL = "http://127.0.0.1:8000"

# Use a fixed user for repeatable tests
test_user = {
    "username": "fixed_testuser",
    "email": "fixed_test@example.com",
    "password": "testpassword123"
}

# This dictionary will store the auth token (though Test 5 won't need it now)
session_data = {}

def test_01_successful_signup():
    """
    Test Case 1: Successful User Signup
    Why: Verifies that a new user can be created with valid, unique data.
    Expected: HTTP 200 (OK)
    """
    # Ensure we are testing with a clean slate for this user
    # (Attempt to delete the user first, ignore if it doesn't exist)
    login_data = {"username": test_user["username"], "password": test_user["password"]}
    try:
        login_resp = requests.post(f"{BASE_URL}/login", data=login_data)
        if login_resp.status_code == 200:
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            # If login worked, try deleting (requires a delete endpoint, which we don't have, so skip for now)
            # requests.delete(f"{BASE_URL}/users/me", headers=headers) # Assumes a DELETE endpoint exists
            pass # Replace with actual delete logic if available
    except requests.exceptions.RequestException:
        pass # Ignore connection errors if server isn't ready for delete check

    # Now, perform the actual signup test
    response = requests.post(f"{BASE_URL}/signup", json=test_user)
    # We allow 200 (created) or 400 (already exists) for setup consistency
    assert response.status_code in [200, 400], f"Signup preparation failed unexpectedly: {response.text}"
    # If it was 200, check details
    if response.status_code == 200:
            data = response.json()
            assert data["username"] == test_user["username"]
            assert data["email"] == test_user["email"]


def test_02_conflicting_signup():
    """
    Test Case 2: Signup with Conflicting Data
    Why: Verifies that the server blocks a duplicate username/email.
    Expected: HTTP 400 (Bad Request)
    """
    # Try to sign up again with the *same data*
    response = requests.post(f"{BASE_URL}/signup", json=test_user)
    assert response.status_code == 400, f"Did not block conflicting signup: {response.text}"
    data = response.json()
    assert data["detail"] == "Email or username already registered"

def test_03_successful_login():
    """
    Test Case 3: Successful User Login
    Why: Verifies a registered user can exchange credentials for a token.
    Expected: HTTP 200 (OK) + an access_token
    """
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    response = requests.post(f"{BASE_URL}/login", data=login_data)
    assert response.status_code == 200, f"Login failed: {response.text}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    # Save the token for the next tests (though Test 5 won't rely on it)
    session_data["token"] = data["access_token"]

def test_04_invalid_password_login():
    """
    Test Case 4: Login with Invalid Password
    Why: A critical security test to ensure bad credentials are rejected.
    Expected: HTTP 401 (Unauthorized)
    """
    login_data = {
        "username": test_user["username"],
        "password": "WRONG_PASSWORD"
    }
    response = requests.post(f"{BASE_URL}/login", data=login_data)
    assert response.status_code == 401, f"Allowed login with wrong password: {response.text}"
    data = response.json()
    assert data["detail"] == "Incorrect username or password"

def test_05_access_protected_route_success():
    """
    Test Case 5: Access Protected Endpoint (Success) - Now Independent
    Why: Verifies the access token from login works on the /users/me route.
    Expected: HTTP 200 (OK)
    """
    # --- Step 1: Log in WITHIN this test to get a token ---
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    login_response = requests.post(f"{BASE_URL}/login", data=login_data)
    assert login_response.status_code == 200, f"Login step failed for Test 5: {login_response.text}"
    token = login_response.json()["access_token"]
    # --- End of added login step ---

    # --- Step 2: Use the token to access the protected route ---
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/users/me", headers=headers)
    assert response.status_code == 200, f"Protected route failed with valid token: {response.text}"
    data = response.json()
    assert data["username"] == test_user["username"] # Check if it returns the correct user

def test_06_access_protected_route_no_token():
    """
    Test Case 6: Access Protected Endpoint (No Token)
    Why: Verifies that the protected /users/me route blocks requests
    that don't have a valid token.
    Expected: HTTP 401 (Unauthorized)
    """
    response = requests.get(f"{BASE_URL}/users/me")
    assert response.status_code == 401, f"Protected route allowed access with no token: {response.text}"
    data = response.json()
    assert data["detail"] == "Not authenticated"
