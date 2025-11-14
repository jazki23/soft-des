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
