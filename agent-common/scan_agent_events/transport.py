"""HTTP retry and acknowledgement rules shared by both scan agents."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
import json
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def retry_delay(value, fallback):
    if not value:
        return fallback
    try:
        delay = int(value)
        return delay if delay >= 0 else fallback
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(0, (retry_at - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return fallback


def send_event(endpoint, body, token):
    request = Request(
        endpoint, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    # Freeze the payload (including its event time) before entering this loop.
    # A lost acknowledgement must resend the same event, not create a new fact.
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        retry_after = None
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8", errors="replace")
            try:
                confirmation = json.loads(body)
            except ValueError:
                confirmation = None
            if (not isinstance(confirmation, dict)
                    or type(confirmation.get("id")) is not int
                    or confirmation["id"] <= 0):
                print("Scan Results Portal returned no valid task acknowledgement", file=sys.stderr)
                return 1
            print(body)
            return 0
        except HTTPError as error:
            retry_after = error.headers.get("Retry-After") if error.headers else None
            try:
                with error:
                    body = error.read(4096).decode("utf-8", errors="replace")
            except (OSError, HTTPException) as read_error:
                body = f"Unable to read error response: {read_error}"
            failure = f"Scan Results Portal rejected event (HTTP {error.code}): {body}"
            status = 22
            if error.code not in (408, 429, 500, 502, 503, 504):
                print(failure, file=sys.stderr)
                return status
        except (OSError, HTTPException) as error:
            # Includes urllib network failures, socket timeouts and truncated
            # responses after the Portal may already have accepted the event.
            failure = f"Unable to contact Scan Results Portal: {error}"
            status = 1

        if attempt == max_attempts:
            print(failure, file=sys.stderr)
            return status
        delay = retry_delay(retry_after, attempt)
        if delay > 30:
            # Do not stall an agent or violate the server's requested delay.
            # Report failure; the durable outbox retains the event for replay.
            print(f"{failure}; Retry-After exceeds the retry window", file=sys.stderr)
            return status
        print(f"{failure}; retry {attempt + 1}/{max_attempts} in {delay:g}s", file=sys.stderr)
        time.sleep(delay)
