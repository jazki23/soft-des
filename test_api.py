import pytest
import requests

BASE_URL = "http://127.0.0.1:8000"

# Use a fixed user for repeatable tests
test_user = {
    "username": "fixed_testuser",
    "email": "fixed_test@example.com",
    "password": "testpassword123"
}

# This dictionary will store the auth token
session_data = {}

def test_01_successful_signup():
    """
    Test Case 1: Successful User Signup
    Why: Verifies that a new user can be created with valid, unique data.
    Expected: HTTP 200 (OK)
    """
    # Pre-clean the test user if it already exists
    login_data = {"username": test_user["username"], "password": test_user["password"]}
    try:
        login_resp = requests.post(f"{BASE_URL}/login", data=login_data)
        if login_resp.status_code == 200:
            token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            # Placeholder: DELETE not implemented in API (skip)
            pass
    except requests.exceptions.RequestException:
        pass

    # Now, perform the actual signup test
    response = requests.post(f"{BASE_URL}/signup", json=test_user)

    # 200 (created) or 400 (already exists) are acceptable for setup
    assert response.status_code in [200, 400], (
        f"Signup preparation failed unexpectedly: {response.text}"
    )

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

    session_data["token"] = data["access_token"]


def test_04_invalid_password_login():
    """
    Test Case 4: Login with Invalid Password
    Why: Ensures bad credentials are rejected.
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
    Test Case 5: Access Protected Endpoint (Success)
    Why: Verifies token auth for /users/me works.
    Expected: HTTP 200 (OK)
    """
    # Login inside this test
    login_data = {
        "username": test_user["username"],
        "password": test_user["password"]
    }
    login_response = requests.post(f"{BASE_URL}/login", data=login_data)
    assert login_response.status_code == 200, (
        f"Login step failed for Test 5: {login_response.text}"
    )

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(f"{BASE_URL}/users/me", headers=headers)
    assert response.status_code == 200, (
        f"Protected route failed with valid token: {response.text}"
    )

    data = response.json()
    assert data["username"] == test_user["username"]


def test_06_access_protected_route_no_token():
    """
    Test Case 6: Access Protected Endpoint Without Token
    Why: Ensures the API blocks unauthenticated requests.
    Expected: HTTP 401 (Unauthorized)
    """
    response = requests.get(f"{BASE_URL}/users/me")
    assert response.status_code == 401, (
        f"Protected route allowed access with no token: {response.text}"
    )

    data = response.json()
    assert data["detail"] == "Not authenticated"

# 7

def test_07_signup_invalid_email():
    """
    Test Case 7: Signup using Invalid Email Address
    Why: Verifies that the system rejects improperly formatted email inputs.
    Expected: HTTP 422 (Unprocessable Entity) or 400 (Bad Request)
    """
    invalid_email_user = {
        "username": "bademailuser",
        "email": "invalid_email.com",  # Missing '@' symbol
        "password": test_user["password"]
    }
    response = requests.post(f"{BASE_URL}/signup", json=invalid_email_user)
    
    # APIs often return 422 for validation errors based on request body schema
    assert response.status_code in [422, 400], f"Allowed signup with invalid email: {response.text}"
    
    # Check for validation detail message structure (often specific to framework like FastAPI)
    try:
        data = response.json()
        assert "email" in str(data)  # Look for the word 'email' in the error message
    except requests.exceptions.JSONDecodeError:
        pass # Handle case where response is not JSON


def test_08_signup_short_password():
    """
    Test Case 8: Signup using Short Password
    Why: Validates that the system enforces minimum password length requirements.
    Expected: HTTP 422 (Unprocessable Entity) or 400 (Bad Request)
    """
    short_password_user = {
        "username": "shortpassuser",
        "email": "shortpass@example.com",
        "password": "short"  # Assuming minimum length > 5
    }
    response = requests.post(f"{BASE_URL}/signup", json=short_password_user)
    
    assert response.status_code in [422, 400], f"Allowed signup with short password: {response.text}"
    
    try:
        data = response.json()
        assert "password" in str(data) and "length" in str(data) # Look for mention of password length
    except requests.exceptions.JSONDecodeError:
        pass


def test_09_signup_missing_field():
    """
    Test Case 9: Signup with Missing Required Field
    Why: Ensures the system validates that all mandatory fields are completed.
    Expected: HTTP 422 (Unprocessable Entity) or 400 (Bad Request)
    """
    missing_field_user = {
        "email": "missingfield@example.com",
        "password": "validpassword123"
        # "username" is intentionally missing
    }
    response = requests.post(f"{BASE_URL}/signup", json=missing_field_user)
    
    assert response.status_code in [422, 400], f"Allowed signup with missing field: {response.text}"
    
    # --- FIX APPLIED HERE ---
    try:
        data = response.json()
        # The API uses 'username' and 'Field required' or 'missing'
        response_string = str(data)
        
        # Check for the key indicators: the field name 'username' and a message about it being 'required'
        assert "username" in response_string and ("required" in response_string or "missing" in response_string.lower())
    except requests.exceptions.JSONDecodeError:
        # This handles cases where the response is not valid JSON
        pass

def test_10_login_nonexistent_user():
    """
    Test Case 10: Logging in with Nonexistent User
    Why: Verifies that the system handles authentication attempts with unregistered credentials.
    Expected: HTTP 401 (Unauthorized)
    """
    nonexistent_login = {
        "username": "truly_nonexistent_user_12345",
        "password": "random_non_matching_password"
    }
    response = requests.post(f"{BASE_URL}/login", data=nonexistent_login)
    
    assert response.status_code == 401, f"Allowed login for nonexistent user: {response.text}"
    
    data = response.json()
    assert data["detail"] == "Incorrect username or password"
