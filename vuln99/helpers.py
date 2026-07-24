import time

from flask import session


def enumeration_guard(id_value, guard_key: str, window_seconds: int = 20, max_distinct: int = 5) -> bool:
    """medium-tier mitigation for the IDOR lessons: not an ownership
    check at all, just a per-session rate limiter that blocks once too
    many *distinct* ids are looked up in a short window. This is a real
    pattern seen in the wild -- "IDOR is fine, we rate-limit it" -- and
    it's still bypassable: slow down the requests, or start a fresh
    session (log out/in, or a new browser/incognito window/curl with no
    cookie jar) to reset the counter. Returns True if the request
    should be blocked.
    """
    now = time.time()
    seen = session.get(guard_key, [])
    seen = [(i, t) for (i, t) in seen if now - t < window_seconds]
    distinct_ids = {i for i, _ in seen}
    blocked = id_value not in distinct_ids and len(distinct_ids) >= max_distinct
    if not blocked:
        seen.append((id_value, now))
    session[guard_key] = seen
    return blocked


def is_logged_in() -> bool:
    return bool(session.get("user_id"))


def current_user():
    if not is_logged_in():
        return None
    return {
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role"),
    }


def is_admin() -> bool:
    """Session-based (correct) admin check — used at 'hard' difficulty."""
    return session.get("role") == "admin"
