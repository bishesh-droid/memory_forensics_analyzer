import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Role:
    name: str
    permissions: list
    description: str = ""


@dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    role: str
    created_at: str
    last_login: str
    active: bool = True
    api_key: str = ""


BUILT_IN_ROLES = {
    "admin": Role("admin", [
        "analyze", "scan", "report", "case_manage", "user_manage",
        "config", "export", "api_access", "delete",
    ], "Full system access"),
    "analyst": Role("analyst", [
        "analyze", "scan", "report", "case_manage", "export", "api_access",
    ], "Forensic analyst"),
    "viewer": Role("viewer", [
        "report", "api_access",
    ], "Read-only access"),
    "api": Role("api", [
        "analyze", "scan", "api_access",
    ], "API-only access"),
}


class RBACManager:

    def __init__(self, db_path: str = ""):
        self._db_path = db_path or str(Path.home() / ".mfa" / "users.json")
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._users: dict[str, User] = {}
        self._roles: dict[str, Role] = dict(BUILT_IN_ROLES)
        self._sessions: dict[str, str] = {}
        self._audit_log: list = []
        self._load()

    def create_user(self, username: str, email: str, password: str,
                    role: str = "analyst") -> User:
        if role not in self._roles:
            raise ValueError(f"Unknown role: {role}")
        if any(u.username == username for u in self._users.values()):
            raise ValueError(f"Username already exists: {username}")

        user_id = str(uuid.uuid4())[:8]
        user = User(
            id=user_id, username=username, email=email,
            password_hash=self._hash_password(password),
            role=role,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            last_login="",
            api_key=hashlib.sha256(f"{user_id}:{time.time()}".encode()).hexdigest()[:32],
        )
        self._users[user_id] = user
        self._save()
        self._log("user_created", username, f"Role: {role}")
        return user

    def authenticate(self, username: str, password: str) -> Optional[str]:
        for user in self._users.values():
            if user.username == username and user.active:
                if self._verify_password(password, user.password_hash):
                    session_token = hashlib.sha256(
                        f"{user.id}:{time.time()}:{uuid.uuid4()}".encode()
                    ).hexdigest()
                    self._sessions[session_token] = user.id
                    user.last_login = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._save()
                    self._log("login", username, "Success")
                    return session_token
        self._log("login_failed", username, "Invalid credentials")
        return None

    def authenticate_api_key(self, api_key: str) -> Optional[User]:
        for user in self._users.values():
            if user.api_key == api_key and user.active:
                return user
        return None

    def authorize(self, session_token: str, permission: str) -> bool:
        user_id = self._sessions.get(session_token)
        if not user_id:
            return False
        user = self._users.get(user_id)
        if not user or not user.active:
            return False
        role = self._roles.get(user.role)
        if not role:
            return False
        return permission in role.permissions

    def get_user(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    def get_user_by_session(self, session_token: str) -> Optional[User]:
        user_id = self._sessions.get(session_token)
        return self._users.get(user_id) if user_id else None

    def list_users(self) -> list:
        return list(self._users.values())

    def deactivate_user(self, user_id: str) -> bool:
        user = self._users.get(user_id)
        if user:
            user.active = False
            self._save()
            self._log("user_deactivated", user.username, "")
            return True
        return False

    def create_role(self, name: str, permissions: list,
                    description: str = "") -> Role:
        role = Role(name=name, permissions=permissions, description=description)
        self._roles[name] = role
        self._save()
        return role

    def get_audit_log(self, limit: int = 100) -> list:
        return self._audit_log[-limit:]

    def logout(self, session_token: str):
        if session_token in self._sessions:
            del self._sessions[session_token]

    def _hash_password(self, password: str) -> str:
        salt = uuid.uuid4().hex
        return f"{salt}:{hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        parts = password_hash.split(":", 1)
        if len(parts) != 2:
            return False
        salt, stored_hash = parts
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == stored_hash

    def _log(self, action: str, user: str, detail: str):
        self._audit_log.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "user": user,
            "detail": detail,
        })

    def _save(self):
        data = {
            "users": {uid: asdict(u) for uid, u in self._users.items()},
            "roles": {name: asdict(r) for name, r in self._roles.items()
                      if name not in BUILT_IN_ROLES},
        }
        with open(self._db_path, "w") as f:
            json.dump(data, f, indent=2)

    def _load(self):
        if not Path(self._db_path).exists():
            return
        try:
            with open(self._db_path) as f:
                data = json.load(f)
            for uid, udata in data.get("users", {}).items():
                self._users[uid] = User(**udata)
            for name, rdata in data.get("roles", {}).items():
                self._roles[name] = Role(**rdata)
        except Exception as e:
            logger.warning("Failed to load RBAC data: %s", e)
