"""
HTTP client for the NVD (National Vulnerability Database) API 2.0.

Handles rate limiting, pagination, retries, and API key authentication.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from nvd_checker.nvd.models import CVERecord

logger = logging.getLogger("nvd_checker")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PAGE_SIZE = 50
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds, multiplied by attempt number


class NVDClient:
    """Client for the NVD CVE API 2.0.

    Args:
        api_key: Optional NVD API key for higher rate limits.
        rate_limit_delay: Seconds between requests. Defaults to 6s
            without key, 0.6s with key.
    """

    def __init__(
        self,
        api_key: str | None = None,
        rate_limit_delay: float | None = None,
    ) -> None:
        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay or (0.6 if api_key else 6.0)
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "nvd-checker/1.0.0",
            "Accept": "application/json",
        })
        if api_key:
            self._session.headers["apiKey"] = api_key
        self._last_request_time: float = 0

    def search_by_keyword(
        self, keyword: str, results_per_page: int = DEFAULT_PAGE_SIZE
    ) -> list[CVERecord]:
        """Search CVEs by keyword in descriptions."""
        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }
        return self._paginated_request(params)

    def search_by_cpe(
        self, cpe_name: str, is_vulnerable: bool = True
    ) -> list[CVERecord]:
        """Search CVEs by CPE name."""
        params: dict[str, Any] = {"cpeName": cpe_name}
        if is_vulnerable:
            params["isVulnerable"] = ""
        return self._paginated_request(params)

    def get_cve(self, cve_id: str) -> CVERecord | None:
        """Get a specific CVE by its ID."""
        params: dict[str, Any] = {"cveId": cve_id}
        results = self._paginated_request(params)
        return results[0] if results else None

    def _paginated_request(
        self, params: dict[str, Any]
    ) -> list[CVERecord]:
        """Execute a paginated request against the NVD API."""
        all_records: list[CVERecord] = []
        start_index = 0
        total_results = None

        while total_results is None or start_index < total_results:
            params["startIndex"] = start_index
            data = self._make_request(params)
            if data is None:
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                try:
                    record = CVERecord.from_api_response(vuln)
                    all_records.append(record)
                except Exception as e:
                    logger.warning(f"Error parsing CVE record: {e}")

            start_index += len(vulnerabilities)

            # Don't paginate for small result sets
            if total_results <= start_index:
                break

            logger.debug(
                f"  Fetched {start_index}/{total_results} results..."
            )

        return all_records

    def _make_request(self, params: dict[str, Any]) -> dict | None:
        """Make a single API request with rate limiting and retries."""
        self._rate_limit()

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self._session.get(
                    NVD_API_BASE, params=params, timeout=30
                )

                if response.status_code == 200:
                    return response.json()

                if response.status_code in (403, 429, 503):
                    wait = RETRY_BACKOFF * attempt
                    logger.warning(
                        f"Rate limited ({response.status_code}), "
                        f"retrying in {wait}s... (attempt {attempt}/{MAX_RETRIES})"
                    )
                    time.sleep(wait)
                    continue

                logger.error(
                    f"NVD API error {response.status_code}: "
                    f"{response.text[:200]}"
                )
                return None

            except requests.RequestException as e:
                if attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF * attempt
                    logger.warning(
                        f"Request failed: {e}, "
                        f"retrying in {wait}s... ({attempt}/{MAX_RETRIES})"
                    )
                    time.sleep(wait)
                else:
                    logger.error(f"Request failed after {MAX_RETRIES} attempts: {e}")
                    return None

        return None

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()
