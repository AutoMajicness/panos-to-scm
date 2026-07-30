"""SCM API client wrapper."""

import logging
import time
from urllib.parse import parse_qsl, urlencode


class ApiRequestError(RuntimeError):
    """Raised when an SCM API request fails after retries."""


class PanApiHandler:
    BASE_URL = "https://api.strata.paloaltonetworks.com"

    def __init__(self, session):
        self.session = session
        self.logger = logging.getLogger(__name__)

    def ensure_valid_token(self):
        self.session.ensure_valid_token()

    def get(self, endpoint, params=None, retries=1, delay=0.5):
        self.ensure_valid_token()
        url = self._build_url(endpoint)
        params = self._normalize_params(params)
        full_url = f"{url}?{urlencode(params)}" if params else url
        self.logger.info(f"Fetching items: {full_url}")

        last_error = None
        for attempt in range(retries + 1):
            try:
                response = self.session.get(url, params=params, timeout=20)
                if response.status_code == 200:
                    payload = response.json()
                    if isinstance(payload, dict):
                        return payload.get("data", payload)
                    if isinstance(payload, list):
                        return payload
                    return payload
                last_error = self._response_error(response)
                self.logger.error(last_error)
            except Exception as exc:
                last_error = str(exc)
                self.logger.error(f"Exception during GET {url}: {last_error}")

            if attempt < retries:
                time.sleep(delay)

        raise ApiRequestError(f"GET failed for {full_url}: {last_error}")

    def post(self, endpoint, item_data, retries=2, delay=0.5):
        return self._write("post", endpoint, item_data, retries, delay, success_status="created")

    def put(self, endpoint, item_data, retries=2, delay=0.5):
        return self._write("put", endpoint, item_data, retries, delay, success_status="updated")

    def _write(self, method_name, endpoint, item_data, retries, delay, success_status):
        url = self._build_url(endpoint)
        request_method = getattr(self.session, method_name)
        for attempt in range(retries + 1):
            try:
                self.ensure_valid_token()
                response = request_method(url, json=item_data, timeout=20)
                if response.status_code in [200, 201, 204]:
                    return {
                        "status": success_status,
                        "message": f"Object {success_status}",
                        "name": item_data.get("name"),
                    }

                error_response = self._safe_json(response)
                if response.status_code in [400, 409] and self._is_already_exists_error(error_response):
                    return {
                        "status": "exists",
                        "message": "Object already exists",
                        "name": item_data.get("name"),
                        "response": error_response,
                    }

                if attempt < retries:
                    logging.warning(f"Retrying {method_name.upper()} for '{item_data.get('name', '')}': {response.text}")
                    time.sleep(delay)
                    continue

                logging.error(f"API Error for '{item_data.get('name', '')}': Response: {response.text}, Status Code: {response.status_code}")
                return {
                    "status": "error",
                    "message": f"Object {success_status} failed",
                    "name": item_data.get("name"),
                    "response": error_response,
                }
            except Exception as exc:
                logging.error(f"Exception occurred for '{item_data.get('name', '')}': {exc}")
                if attempt < retries:
                    time.sleep(delay)
                else:
                    return {
                        "status": "exception",
                        "message": f"Exception: {exc}",
                        "name": item_data.get("name"),
                    }

        return {"status": "error", "message": "Failed after retries", "name": item_data.get("name")}

    @staticmethod
    def _build_url(endpoint):
        if endpoint.startswith("http"):
            return endpoint
        return f"{PanApiHandler.BASE_URL}{endpoint}"

    @staticmethod
    def _normalize_params(params):
        if params is None:
            return {}
        if isinstance(params, str):
            return dict(parse_qsl(params.lstrip("?&")))
        if not isinstance(params, dict):
            raise ValueError(f"Invalid params type: {type(params)}. Expected dict or string.")
        return params

    @staticmethod
    def _safe_json(response):
        try:
            return response.json()
        except ValueError:
            return {"text": response.text}

    @staticmethod
    def _is_already_exists_error(error_response):
        error_text = str(error_response).lower()
        return (
            "object already exists" in error_text
            or "already exists" in error_text
            or "same name" in error_text
            or "name not unique" in error_text
        )

    def _response_error(self, response):
        return f"API Error: {self._safe_json(response)}, Status Code: {response.status_code}"
