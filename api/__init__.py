import requests
import logging
import time
import yaml
from api.config import load_panapi_config, panapi_config_path

class PanApiSession:
    """
    Manages a session with the SASE API, including authentication.
    """
    def __init__(self, runtime_config=None):
        self.session = self._create_session()
        self.token = None
        self.token_expiry_time = None
        self.config = self._load_config()
        if isinstance(runtime_config, dict):
            self.config.update({
                key: value
                for key, value in runtime_config.items()
                if value is not None and str(value).strip()
            })
        self.oauth_session = None

    def _create_session(self):
        session = requests.Session()
        # Configure session as needed (e.g., retries, adapters)
        return session

    def _load_config(self):
        try:
            config = load_panapi_config()
            return {
                'api_url': config.get('api_url', 'https://api.strata.paloaltonetworks.com'),
                'client_id': config.get('client_id'),
                'client_secret': config.get('client_secret'),
                'tsg_id': config.get('tsg_id'),
                'auth_url': config.get('auth_url', 'https://auth.apps.paloaltonetworks.com/oauth2/access_token'),
            }
        except Exception as e:
            logging.error(f"Error loading PAN-API credentials from {panapi_config_path()}: {e}")
            return {
                'api_url': 'https://api.strata.paloaltonetworks.com',
                'auth_url': 'https://auth.apps.paloaltonetworks.com/oauth2/access_token'
            }

    def authenticate(self):
        if not self.token or self.is_token_expired():
            self.token = self.get_access_token()
            if self.token:
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            else:
                raise RuntimeError("Unable to authenticate to SCM; access token was not returned")

    def is_token_expired(self):
        if not self.token_expiry_time:
            return True
        return time.time() >= self.token_expiry_time

    def get_access_token(self):
        """Get OAuth2 access token using client credentials flow."""
        try:
            if not self.config.get('client_id') or not self.config.get('client_secret'):
                logging.error("Client ID or Client Secret not configured")
                return None

            # Prepare the OAuth2 client credentials request
            auth = (self.config['client_id'], self.config['client_secret'])
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            }
            
            scope = f"email profile tsg_id:{self.config.get('tsg_id', '')}"
            data = {
                'grant_type': 'client_credentials',
                'scope': scope
            }

            response = requests.post(
                self.config['auth_url'],
                headers=headers,
                data=data,
                auth=auth,
                timeout=30
            )

            if response.status_code == 200:
                token_data = response.json()
                self.token_expiry_time = time.time() + token_data.get('expires_in', 900) - 60  # 60 second buffer
                logging.info(f"Token will expire at {time.ctime(self.token_expiry_time)}")
                return token_data.get('access_token')
            else:
                logging.error(f"Failed to get access token: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logging.error(f"Error getting access token: {e}")
            return None

    def ensure_valid_token(self):
        """Ensure the session token is valid."""
        self.authenticate()

    def get(self, endpoint, params=None, timeout=20):
        self.authenticate()
        # Check if endpoint is already a full URL
        if isinstance(endpoint, str) and endpoint.startswith('http'):
            url = endpoint
        else:
            # Ensure we don't leave a trailing '?' on the endpoint which can lead to malformed URLs
            endpoint = endpoint.rstrip('?')
            url = f"{self.config['api_url']}{endpoint}"
        try:
            response = self.session.get(url, params=params, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during API request to {url}: {e}")
            raise

    def post(self, endpoint, data=None, headers=None, timeout=20, json=None):
        self.authenticate()

        # Check if endpoint is already a full URL
        if endpoint.startswith('http'):
            url = endpoint
        else:
            endpoint = endpoint.rstrip('?')
            url = f"{self.config['api_url']}{endpoint}"

        # Use json parameter if provided, otherwise use data
        request_data = json if json is not None else data

        try:
            if json is not None:
                response = self.session.post(url, json=json, headers=headers, timeout=timeout)
            else:
                response = self.session.post(url, json=data, headers=headers, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during POST to {url}: {e}")
            raise

    def put(self, endpoint, data=None, headers=None, timeout=20, json=None):
        self.authenticate()

        if endpoint.startswith('http'):
            url = endpoint
        else:
            endpoint = endpoint.rstrip('?')
            url = f"{self.config['api_url']}{endpoint}"

        try:
            if json is not None:
                response = self.session.put(url, json=json, headers=headers, timeout=timeout)
            else:
                response = self.session.put(url, json=data, headers=headers, timeout=timeout)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during PUT to {url}: {e}")
            raise
