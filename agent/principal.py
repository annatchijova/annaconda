"""Who is asking, and whether we actually know.

The enterprise catalog (agent/catalog.py) is a real gate: it decides which
department may task which agent, over which data, in which region. But a gate
is only as good as the identity in front of it, and until now the department
arrived in a request body — anybody could type `forensics`.

This module resolves the *principal* behind a tasking and, crucially, records
how confident we are about it:

    authenticated  a Google identity token was presented and verified, and its
                   subject maps to a department in the deployment's roster
    asserted       the department was claimed with no verified identity

Both are allowed to run by default, because the public demo has no identity
provider in front of it — but they are never conflated. The principal travels
into the cycle and is sealed into the case's mission journal, so a record shows
who ran a cycle and whether that claim was verified. Set
``VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL=true`` and an asserted principal is
refused outright: that is the production posture, and it is one env var, not a
rewrite.

Why not simply require it always: refusing every unauthenticated tasking would
make the deployed demo unusable, and pretending an asserted department is an
authenticated one would be exactly the kind of quiet overclaim this project
exists to avoid. Naming the difference on every record is the honest third
option.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from agent import catalog

log = logging.getLogger("annaconda.principal")

REQUIRE_AUTH_ENV = "VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL"
ROSTER_ENV = "VIGIA_DEPARTMENT_ROSTER"
AUDIENCE_ENV = "VIGIA_EXPECTED_AUDIENCE"


class UnauthenticatedPrincipalError(PermissionError):
    """An asserted department was refused because this deployment requires a
    verified identity."""


DEFAULT_DEPARTMENT_ENV = "VIGIA_DEFAULT_DEPARTMENT"

# What an unauthenticated caller that names no department is treated as. The
# deployed demo has no identity provider, so this is the posture that keeps it
# usable — and it was, accidentally, the most privileged department this
# deployment publishes: incident-response is cleared to task every agent in the
# catalog (red-team A-5). That may still be the right demo setting, but it has
# to be a stated posture rather than whichever constant happened to be in scope
# at the call site, so it is named here, overridable, reported on /health, and
# refused outright when it is not a published department.
DEFAULT_DEPARTMENT = "incident-response"


def default_department() -> Optional[str]:
    """The department an unauthenticated caller is treated as, or None when the
    deployment's configured default is not a published department — in which
    case an unauthenticated tasking is refused rather than quietly promoted."""
    configured = os.environ.get(DEFAULT_DEPARTMENT_ENV, "").strip().lower()
    candidate = configured or DEFAULT_DEPARTMENT
    if candidate not in catalog.DEPARTMENTS:
        if configured:
            log.warning("%s names unknown department %r — unauthenticated "
                        "taskings will be refused", DEFAULT_DEPARTMENT_ENV,
                        configured)
        return None
    return candidate


def require_authenticated() -> bool:
    return os.environ.get(REQUIRE_AUTH_ENV, "").strip().lower() in {"1", "true", "yes"}


def _roster() -> dict:
    """email -> department, from ``VIGIA_DEPARTMENT_ROSTER``.

    Format: ``someone@example.com:forensics,sa@project.iam...:incident-response``
    Kept in the environment rather than in code so a deployment's roster is not
    a source change — and so this repo carries no real identities.
    """
    raw = os.environ.get(ROSTER_ENV, "").strip()
    roster = {}
    for pair in raw.split(","):
        if not pair.strip():
            continue
        email, _, dept = pair.partition(":")
        email, dept = email.strip().lower(), dept.strip().lower()
        if email and dept in catalog.DEPARTMENTS:
            roster[email] = dept
        elif email:
            log.warning("roster entry for %s names unknown department %r — ignored",
                        email, dept)
    return roster


def verify_identity_token(token: str) -> Optional[str]:
    """Verify a Google identity token and return its subject email.

    Returns None when the token cannot be verified for any reason — expired,
    wrong audience, unreachable certificates. A token we could not check is
    treated exactly like no token at all: it never upgrades a principal to
    authenticated.
    """
    if not token:
        return None

    # Without an expected audience there is no audience check at all: google-auth
    # verifies 'aud' only when one is supplied, so a correctly signed token
    # minted for a COMPLETELY DIFFERENT service would verify here and, if its
    # subject happens to be rostered, authenticate as that person. That is the
    # confused-deputy case audience verification exists to prevent. A token we
    # cannot fully check is treated exactly like no token at all — the rule this
    # module already states — so an unconfigured audience means unauthenticated,
    # not "authenticated without that check".
    audience = os.environ.get("VIGIA_EXPECTED_AUDIENCE", "").strip()
    if not audience:
        log.warning(
            "%s is not set, so an identity token's audience cannot be verified "
            "— refusing to treat the principal as authenticated. Set it to this "
            "service's URL to accept identity tokens.", AUDIENCE_ENV)
        return None

    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        claims = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), audience)
    except Exception as exc:  # noqa: BLE001 — any failure is a failure to verify
        log.warning("identity token could not be verified (%s) — treating the "
                    "principal as asserted", exc)
        return None
    email = claims.get("email")
    if not email or not claims.get("email_verified", True):
        return None
    return str(email).lower()


def resolve(*, authorization_header: Optional[str] = None,
            claimed_department: Optional[str] = None,
            default_department: Optional[str] = None) -> dict:
    """Resolve the principal for one tasking.

    A verified identity in the deployment's roster wins over anything the
    request claims — a caller cannot present a SOC token and ask to run as
    forensics. With no verified identity, the claimed department is used and
    the principal is marked ``asserted``.
    """
    token = ""
    if authorization_header and authorization_header.lower().startswith("bearer "):
        token = authorization_header.split(" ", 1)[1].strip()

    email = verify_identity_token(token) if token else None
    if email:
        department = _roster().get(email)
        if department:
            return {"department": department, "identity": email,
                    "authenticated": True, "how": "verified identity token"}
        # A real, verified identity this deployment has not rostered used to be
        # refused outright — while the same caller sending NO header at all was
        # allowed, as whatever department it asked for (red-team A-5). That is
        # an inversion, not a defence: anyone holding such a token simply drops
        # it. Authenticating must never leave a caller worse off than staying
        # anonymous, so this falls through to the asserted path — with the
        # identity we did verify recorded, which is strictly more than an
        # anonymous caller gives us, and with `authenticated` still False,
        # because a department nobody rostered is exactly that.
        log.warning("verified identity %s is not in the department roster — "
                    "treating this tasking as asserted, not refusing it", email)
        return {"department": _claimed(claimed_department, default_department),
                "identity": email, "authenticated": False,
                "how": "verified identity, not in the department roster — "
                       "treated as asserted"}

    return {"department": _claimed(claimed_department, default_department),
            "identity": None, "authenticated": False,
            "how": "asserted in the request, no verified identity"}


def _claimed(claimed: Optional[str], fallback: Optional[str]) -> Optional[str]:
    """The department an unverified request may act as, or None.

    A claimed department was previously lowercased and returned as-is, whatever
    it said. Nothing between here and the catalog rejected it, so an arbitrary
    caller-chosen string travelled into the case's mission journal and was
    SEALED there as the department that ran the cycle (red-team A-5). A claim
    this deployment does not publish is not a department; it resolves to None
    and `enforce` refuses it.
    """
    department = (claimed or "").strip().lower()
    if department:
        if department in catalog.DEPARTMENTS:
            return department
        log.warning("request claimed unknown department %r — refusing rather "
                    "than recording it", claimed)
        return None
    return fallback or None


def enforce(principal: dict) -> dict:
    """Apply the deployment's posture. Returns the principal, or refuses."""
    if not principal.get("department"):
        raise UnauthenticatedPrincipalError(
            f"no department could be resolved for this tasking "
            f"({principal.get('how')})")
    if require_authenticated() and not principal.get("authenticated"):
        raise UnauthenticatedPrincipalError(
            f"this deployment requires a verified identity and the principal is "
            f"{principal.get('how')} — refusing to task the fleet")
    return principal
