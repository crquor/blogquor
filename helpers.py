from functools import wraps
from flask import redirect, url_for, session
import requests
import re

# Function to require login for the required pages

def login_required(f):
    """
    Decorator to require login for specific views.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            # Redirect to login page if the user is not logged in
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Function to validate the email

def validate_email(email):

    # API endpoint and key
    url = "https://api.hunter.io/v2/email-verifier"
    key = "51d09a0295f28215643c558045cd7254952840e5"

    # Parameters
    params = {
        "email": email,
        "api_key": key
    }

    # Make the GET request
    try: 
        response = requests.get(url, params = params)

        # Check if the request was successful
        if response.status_code == 200:

            # Parse the data to json
            data = response.json()
            print(data)

            # Return true if the email is not disposable, and mx records for the email exist , and email's format is correct, and the smtp server responds
            if data["data"]["regexp"] and data["data"]["mx_records"] and data["data"]["smtp_server"] and not data["data"]["disposable"] and not data["data"]["result"] == "undeliverable":
                return True
            # Else return false i.e. the email is not valid
            else:
                return False
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
        
    except Exception as e:
        print(f"Error: {e}")
        return None


# Function to validate the password's strength
def ispwd_strong(password):

    # Define the pattern for password
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

    # If the password matches the pattern, return true. Else, return false
    if re.match(pattern,password):
        return True
    return False