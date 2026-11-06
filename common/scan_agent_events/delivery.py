"""Persist, deliver and replay events without scanner-specific field knowledge."""

import os
import sqlite3
import sys
from urllib.parse import urlsplit

from .outbox import EventOutbox
from .transport import send_event


def deliver_event(kind, body_factory=None):
    """Deliver lazily built bytes, or replay one batch when no factory is supplied."""
    portal_url = os.environ["SCAN_RESULTS_PORTAL_URL"].rstrip("/")
    token = os.environ["SCAN_SERVICE_INGEST_TOKEN"]
    parsed = urlsplit(portal_url)
    # Only destinations, never credentials, may enter the recovery database.
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        print("SCAN_RESULTS_PORTAL_URL must be an HTTP(S) base URL without credentials, query or fragment",
              file=sys.stderr)
        return 1
    endpoint = f"{portal_url}/api/v1/{kind}/events"
    workdir = os.environ.get("JENKINS_AGENT_WORKDIR", "/home/jenkins/agent")
    try:
        with EventOutbox(workdir, kind) as outbox:
            if body_factory is None:
                pending = outbox.pending(endpoint)
            else:
                body = body_factory()
                pending = [(outbox.store(endpoint, body), body)]
            status = 0
            delivered = 0
            for event_id, body in pending:
                outbox.attempted(event_id)
                result = send_event(endpoint, body, token)
                if result == 0:
                    outbox.acknowledge(event_id)
                    delivered += 1
                else:
                    status = status or result
                    print(f"Event {event_id} retained in outbox; retry with send-{kind}-event replay",
                          file=sys.stderr)
            if body_factory is None:
                print(f"Replayed {delivered}/{len(pending)} events; "
                      f"{outbox.count(endpoint)} pending for this Portal")
            return status
    except (OSError, sqlite3.Error) as error:
        print(f"Unable to use event outbox: {error}", file=sys.stderr)
        return 1
