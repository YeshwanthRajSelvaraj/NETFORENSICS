"""
NetForensics — Multi-Tenant Architecture + Role-Based Access Control (RBAC)
=============================================================================
Enterprise-grade multi-tenancy with hierarchical RBAC, JWT authentication,
API key management, and comprehensive audit logging.

Roles:
  - platform_admin : Full system access across all tenants
  - tenant_admin   : Manage users, configs within a single tenant
  - soc_manager    : SOC operations + investigation management
  - soc_analyst    : Alert triage, investigation, threat hunting
  - investigator   : Read + investigation workflows only
  - readonly       : Dashboard read-only access

Tenant isolation:
  - Every DB entity carries tenant_id
  - Middleware injects tenant context from JWT/API key
  - Query filters are automatic via TenantContext
"""

import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("netforensics.enterprise.rbac")

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

ROLES = {
    "platform_admin": {
        "level": 100,
        "description": "Full platform access across all tenants",
        "permissions": {"*"},
    },
    "tenant_admin": {
        "level": 80,
        "description": "Full access within assigned tenant",
        "permissions": {
            "users:read", "users:write", "users:delete",
            "sessions:read", "sessions:write", "sessions:delete",
            "alerts:read", "alerts:write", "alerts:assign", "alerts:close",
            "investigations:read", "investigations:write", "investigations:close",
            "intel:read", "intel:write",
            "ml:read", "ml:train", "ml:configure",
            "reports:read", "reports:generate",
            "config:read", "config:write",
            "audit:read",
            "siem:read", "siem:write",
        },
    },
    "soc_manager": {
        "level": 60,
        "description": "SOC operations management",
        "permissions": {
            "sessions:read", "sessions:write",
            "alerts:read", "alerts:write", "alerts:assign", "alerts:close",
            "investigations:read", "investigations:write", "investigations:close",
            "intel:read", "intel:write",
            "ml:read", "ml:train",
            "reports:read", "reports:generate",
            "audit:read",
            "siem:read",
        },
    },
    "soc_analyst": {
        "level": 40,
        "description": "Alert triage and investigation",
        "permissions": {
            "sessions:read",
            "alerts:read", "alerts:write", "alerts:assign",
            "investigations:read", "investigations:write",
            "intel:read",
            "ml:read",
            "reports:read", "reports:generate",
        },
    },
    "investigator": {
        "level": 30,
        "description": "Investigation-focused access",
        "permissions": {
            "sessions:read",
            "alerts:read",
            "investigations:read", "investigations:write",
            "intel:read",
            "reports:read",
        },
    },
    "readonly": {
        "level": 10,
        "description": "Read-only dashboard access",
        "permissions": {
            "sessions:read", "alerts:read", "investigations:read",
            "intel:read", "ml:read", "reports:read",
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Tenant:
    id: str = ""
    name: str = ""
    slug: str = ""
    plan: str = "enterprise"        # community, professional, enterprise
    max_users: int = 100
    max_sessions: int = 10000
    features: List[str] = field(default_factory=lambda: [
        "ml_detection", "siem_integration", "stix_taxii",
        "geoip", "investigation", "reports",
    ])
    active: bool = True
    created_at: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()
        if not self.slug and self.name:
            self.slug = self.name.lower().replace(" ", "_")[:32]

    def has_feature(self, feature: str) -> bool:
        return feature in self.features or self.plan == "enterprise"


@dataclass
class User:
    id: str = ""
    tenant_id: str = ""
    username: str = ""
    email: str = ""
    display_name: str = ""
    role: str = "soc_analyst"
    password_hash: str = ""
    mfa_enabled: bool = False
    mfa_secret: str = ""
    active: bool = True
    failed_logins: int = 0
    locked_until: str = ""
    last_login: str = ""
    created_at: str = ""
    preferences: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    @property
    def role_level(self) -> int:
        return ROLES.get(self.role, {}).get("level", 0)

    @property
    def permissions(self) -> Set[str]:
        return ROLES.get(self.role, {}).get("permissions", set())

    def has_permission(self, permission: str) -> bool:
        perms = self.permissions
        if "*" in perms:
            return True
        if permission in perms:
            return True
        # Check wildcard: "alerts:*" matches "alerts:read"
        resource = permission.split(":")[0]
        return f"{resource}:*" in perms

    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        try:
            lock_time = datetime.fromisoformat(self.locked_until)
            return datetime.utcnow() < lock_time
        except Exception:
            return False


@dataclass
class APIKey:
    id: str = ""
    user_id: str = ""
    tenant_id: str = ""
    name: str = ""
    key_prefix: str = ""
    key_hash: str = ""
    permissions: List[str] = field(default_factory=lambda: ["sessions:read", "alerts:read"])
    rate_limit: int = 1000          # requests per minute
    expires_at: str = ""
    last_used: str = ""
    created_at: str = ""
    active: bool = True

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return datetime.utcnow() > datetime.fromisoformat(self.expires_at)
        except Exception:
            return False


@dataclass
class AuditEntry:
    id: str = ""
    tenant_id: str = ""
    user_id: str = ""
    username: str = ""
    action: str = ""            # login, create, read, update, delete, export
    resource_type: str = ""     # session, alert, investigation, user, config
    resource_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    timestamp: str = ""
    success: bool = True

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class TenantContext:
    """Injected into every request via middleware."""
    tenant: Optional[Tenant] = None
    user: Optional[User] = None
    api_key: Optional[APIKey] = None
    session_id: str = ""
    ip_address: str = ""

    @property
    def tenant_id(self) -> str:
        return self.tenant.id if self.tenant else ""

    @property
    def user_id(self) -> str:
        return self.user.id if self.user else ""

    def has_permission(self, permission: str) -> bool:
        if self.user:
            return self.user.has_permission(permission)
        if self.api_key:
            if "*" in self.api_key.permissions:
                return True
            return permission in self.api_key.permissions
        return False

    def require_permission(self, permission: str):
        if not self.has_permission(permission):
            raise PermissionError(
                f"Permission denied: '{permission}' required. "
                f"User role: {self.user.role if self.user else 'none'}")


# ═══════════════════════════════════════════════════════════════════════════════
# PASSWORD HASHING (Argon2id-style via PBKDF2-HMAC-SHA256)
# ═══════════════════════════════════════════════════════════════════════════════

class PasswordHasher:
    ITERATIONS = 600_000                # OWASP recommended
    SALT_LENGTH = 32
    HASH_LENGTH = 64

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(PasswordHasher.SALT_LENGTH)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt,
            PasswordHasher.ITERATIONS, dklen=PasswordHasher.HASH_LENGTH)
        return f"pbkdf2:sha256:{PasswordHasher.ITERATIONS}${salt.hex()}${dk.hex()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        try:
            parts = stored_hash.split("$")
            header = parts[0]
            salt = bytes.fromhex(parts[1])
            expected = parts[2]
            iterations = int(header.split(":")[-1])
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt,
                iterations, dklen=PasswordHasher.HASH_LENGTH)
            return hmac.compare_digest(dk.hex(), expected)
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════════════════════════
# JWT TOKEN MANAGEMENT (Pure Python HS256)
# ═══════════════════════════════════════════════════════════════════════════════

class JWTManager:
    """Pure-Python JWT (HS256) — no PyJWT dependency."""

    def __init__(self, secret: str = ""):
        self.secret = secret or os.environ.get(
            "NF_JWT_SECRET", secrets.token_hex(32))
        self.access_ttl = 3600          # 1 hour
        self.refresh_ttl = 86400 * 7    # 7 days

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        import base64
        padding = 4 - len(s) % 4
        s += "=" * (padding % 4)
        return base64.urlsafe_b64decode(s)

    def _sign(self, payload: str) -> str:
        header = self._b64url_encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = self._b64url_encode(payload.encode())
        msg = f"{header}.{body}"
        sig = hmac.new(
            self.secret.encode(), msg.encode(), hashlib.sha256).digest()
        return f"{msg}.{self._b64url_encode(sig)}"

    def create_access_token(self, user: User, tenant: Tenant) -> str:
        now = int(time.time())
        payload = json.dumps({
            "sub": user.id,
            "tid": tenant.id,
            "username": user.username,
            "role": user.role,
            "permissions": list(user.permissions),
            "tenant_name": tenant.name,
            "iat": now,
            "exp": now + self.access_ttl,
            "type": "access",
        })
        return self._sign(payload)

    def create_refresh_token(self, user: User, tenant: Tenant) -> str:
        now = int(time.time())
        payload = json.dumps({
            "sub": user.id,
            "tid": tenant.id,
            "iat": now,
            "exp": now + self.refresh_ttl,
            "type": "refresh",
        })
        return self._sign(payload)

    def decode_token(self, token: str) -> Optional[Dict]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Verify signature
            msg = f"{parts[0]}.{parts[1]}"
            expected_sig = hmac.new(
                self.secret.encode(), msg.encode(), hashlib.sha256).digest()
            actual_sig = self._b64url_decode(parts[2])

            if not hmac.compare_digest(expected_sig, actual_sig):
                logger.warning("JWT signature verification failed")
                return None

            payload = json.loads(self._b64url_decode(parts[1]))

            # Check expiry
            if payload.get("exp", 0) < int(time.time()):
                logger.debug("JWT expired")
                return None

            return payload
        except Exception as e:
            logger.warning("JWT decode error: %s", e)
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# API KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class APIKeyManager:
    PREFIX = "nf_"
    KEY_LENGTH = 48

    @classmethod
    def generate_key(cls) -> Tuple[str, str, str]:
        """Returns (full_key, prefix, key_hash)."""
        raw = secrets.token_urlsafe(cls.KEY_LENGTH)
        full_key = f"{cls.PREFIX}{raw}"
        prefix = full_key[:12]
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        return full_key, prefix, key_hash

    @classmethod
    def hash_key(cls, key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    @classmethod
    def validate_format(cls, key: str) -> bool:
        return key.startswith(cls.PREFIX) and len(key) > 20


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITER (Token Bucket)
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self):
        self._buckets: Dict[str, Dict] = {}

    def check(self, key: str, limit: int = 60, window: int = 60) -> Tuple[bool, Dict]:
        now = time.time()
        bucket = self._buckets.get(key)

        if not bucket or now - bucket["window_start"] > window:
            self._buckets[key] = {
                "tokens": limit - 1,
                "window_start": now,
            }
            return True, {"remaining": limit - 1, "limit": limit, "reset": int(now + window)}

        if bucket["tokens"] <= 0:
            return False, {"remaining": 0, "limit": limit,
                           "reset": int(bucket["window_start"] + window)}

        bucket["tokens"] -= 1
        return True, {"remaining": bucket["tokens"], "limit": limit,
                       "reset": int(bucket["window_start"] + window)}


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOGGER
# ═══════════════════════════════════════════════════════════════════════════════

class AuditLogger:
    def __init__(self):
        self._entries: List[AuditEntry] = []
        self._max_entries = 100_000

    def log(self, ctx: TenantContext, action: str,
            resource_type: str = "", resource_id: str = "",
            details: Dict = None, success: bool = True):
        entry = AuditEntry(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            username=ctx.user.username if ctx.user else "api_key",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ctx.ip_address,
            success=success,
        )
        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries:]

        logger.info("AUDIT: [%s] %s %s/%s by %s from %s",
                     ctx.tenant_id[:8] if ctx.tenant_id else "system",
                     action, resource_type, resource_id[:8] if resource_id else "-",
                     entry.username, entry.ip_address)

    def query(self, tenant_id: str = "", user_id: str = "",
              action: str = "", resource_type: str = "",
              since: str = "", limit: int = 100) -> List[Dict]:
        results = self._entries
        if tenant_id:
            results = [e for e in results if e.tenant_id == tenant_id]
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        if action:
            results = [e for e in results if e.action == action]
        if resource_type:
            results = [e for e in results if e.resource_type == resource_type]
        if since:
            results = [e for e in results if e.timestamp >= since]
        return [asdict(e) for e in results[-limit:]]


# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-TENANT MANAGER (In-memory + JSON persistence)
# ═══════════════════════════════════════════════════════════════════════════════

class MultiTenantManager:
    """
    Manages tenants, users, API keys.
    Uses JSON file persistence for lightweight deployment.
    """

    def __init__(self, data_dir: str = "/tmp/nf_enterprise"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}     # hash -> APIKey
        self.jwt = JWTManager()
        self.hasher = PasswordHasher()
        self.key_mgr = APIKeyManager()
        self.rate_limiter = RateLimiter()
        self.audit = AuditLogger()
        self._load()

    def _persist_path(self) -> str:
        return os.path.join(self.data_dir, "rbac_state.json")

    def _load(self):
        path = self._persist_path()
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                for t in data.get("tenants", []):
                    tenant = Tenant(**t)
                    self.tenants[tenant.id] = tenant
                for u in data.get("users", []):
                    user = User(**u)
                    self.users[user.id] = user
                for k in data.get("api_keys", []):
                    key = APIKey(**k)
                    self.api_keys[key.key_hash] = key
                logger.info("RBAC state loaded: %d tenants, %d users, %d API keys",
                             len(self.tenants), len(self.users), len(self.api_keys))
            except Exception as e:
                logger.error("Failed to load RBAC state: %s", e)
        else:
            self._create_default_tenant()

    def _save(self):
        data = {
            "tenants": [asdict(t) for t in self.tenants.values()],
            "users": [asdict(u) for u in self.users.values()],
            "api_keys": [asdict(k) for k in self.api_keys.values()],
        }
        with open(self._persist_path(), "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _create_default_tenant(self):
        """Bootstrap: create default tenant and admin user."""
        tenant = Tenant(
            name="Default Organization",
            slug="default",
            plan="enterprise",
        )
        admin = User(
            tenant_id=tenant.id,
            username="admin",
            email="admin@netforensics.local",
            display_name="Platform Administrator",
            role="platform_admin",
            password_hash=self.hasher.hash_password("admin"),
        )
        self.tenants[tenant.id] = tenant
        self.users[admin.id] = admin
        self._save()
        logger.info("Default tenant '%s' and admin user created", tenant.name)

    # ── Tenant CRUD ───────────────────────────────────────────────────────────

    def create_tenant(self, name: str, plan: str = "enterprise",
                       max_users: int = 100, **kwargs) -> Tenant:
        tenant = Tenant(name=name, plan=plan, max_users=max_users, **kwargs)
        self.tenants[tenant.id] = tenant
        self._save()
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        return self.tenants.get(tenant_id)

    def list_tenants(self) -> List[Dict]:
        return [
            {**asdict(t), "user_count": sum(1 for u in self.users.values()
                                             if u.tenant_id == t.id)}
            for t in self.tenants.values()
        ]

    # ── User CRUD ─────────────────────────────────────────────────────────────

    def create_user(self, tenant_id: str, username: str, password: str,
                     email: str = "", role: str = "soc_analyst",
                     display_name: str = "") -> User:
        if role not in ROLES:
            raise ValueError(f"Invalid role: {role}. Valid: {list(ROLES.keys())}")
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        # Check user limit
        tenant_users = [u for u in self.users.values() if u.tenant_id == tenant_id]
        if len(tenant_users) >= tenant.max_users:
            raise ValueError(f"Tenant user limit reached: {tenant.max_users}")
        # Check uniqueness
        if any(u.username == username for u in self.users.values()):
            raise ValueError(f"Username '{username}' already exists")

        user = User(
            tenant_id=tenant_id,
            username=username,
            email=email,
            display_name=display_name or username,
            role=role,
            password_hash=self.hasher.hash_password(password),
        )
        self.users[user.id] = user
        self._save()
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[User]:
        for u in self.users.values():
            if u.username == username:
                return u
        return None

    def list_users(self, tenant_id: str = "") -> List[Dict]:
        users = self.users.values()
        if tenant_id:
            users = [u for u in users if u.tenant_id == tenant_id]
        return [
            {k: v for k, v in asdict(u).items() if k != "password_hash"}
            for u in users
        ]

    def update_user_role(self, user_id: str, new_role: str) -> User:
        user = self.get_user(user_id)
        if not user:
            raise ValueError("User not found")
        if new_role not in ROLES:
            raise ValueError(f"Invalid role: {new_role}")
        user.role = new_role
        self._save()
        return user

    def deactivate_user(self, user_id: str):
        user = self.get_user(user_id)
        if user:
            user.active = False
            self._save()

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not user.active:
            return None
        if user.is_locked():
            return None

        if not self.hasher.verify_password(password, user.password_hash):
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.locked_until = (
                    datetime.utcnow() + timedelta(minutes=15)).isoformat()
                logger.warning("User %s locked after %d failed attempts",
                                username, user.failed_logins)
            self._save()
            return None

        # Successful login
        user.failed_logins = 0
        user.locked_until = ""
        user.last_login = datetime.utcnow().isoformat()
        self._save()

        tenant = self.get_tenant(user.tenant_id)
        if not tenant or not tenant.active:
            return None

        return {
            "access_token": self.jwt.create_access_token(user, tenant),
            "refresh_token": self.jwt.create_refresh_token(user, tenant),
            "token_type": "bearer",
            "expires_in": self.jwt.access_ttl,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "tenant_id": tenant.id,
                "tenant_name": tenant.name,
                "permissions": list(user.permissions),
            },
        }

    def resolve_context(self, token: str = "", api_key: str = "",
                         ip_address: str = "") -> Optional[TenantContext]:
        """Resolve JWT token or API key into a TenantContext."""
        if token:
            payload = self.jwt.decode_token(token)
            if not payload:
                return None
            user = self.get_user(payload["sub"])
            tenant = self.get_tenant(payload["tid"])
            if not user or not tenant:
                return None
            return TenantContext(
                tenant=tenant, user=user, ip_address=ip_address,
                session_id=str(uuid.uuid4()))

        if api_key:
            key_hash = self.key_mgr.hash_key(api_key)
            ak = self.api_keys.get(key_hash)
            if not ak or not ak.active or ak.is_expired():
                return None
            user = self.get_user(ak.user_id)
            tenant = self.get_tenant(ak.tenant_id)
            if not user or not tenant:
                return None
            ak.last_used = datetime.utcnow().isoformat()
            # Rate limit
            allowed, info = self.rate_limiter.check(
                f"api_key:{ak.id}", limit=ak.rate_limit)
            if not allowed:
                return None
            return TenantContext(
                tenant=tenant, user=user, api_key=ak,
                ip_address=ip_address, session_id=str(uuid.uuid4()))

        return None

    # ── API Key CRUD ──────────────────────────────────────────────────────────

    def create_api_key(self, user_id: str, name: str = "",
                        permissions: List[str] = None,
                        rate_limit: int = 1000,
                        ttl_days: int = 365) -> Tuple[str, APIKey]:
        user = self.get_user(user_id)
        if not user:
            raise ValueError("User not found")

        full_key, prefix, key_hash = self.key_mgr.generate_key()
        ak = APIKey(
            user_id=user_id,
            tenant_id=user.tenant_id,
            name=name or f"api_key_{prefix}",
            key_prefix=prefix,
            key_hash=key_hash,
            permissions=permissions or ["sessions:read", "alerts:read"],
            rate_limit=rate_limit,
            expires_at=(datetime.utcnow() + timedelta(days=ttl_days)).isoformat(),
        )
        self.api_keys[key_hash] = ak
        self._save()
        return full_key, ak

    def revoke_api_key(self, key_id: str):
        for ak in self.api_keys.values():
            if ak.id == key_id:
                ak.active = False
                self._save()
                return True
        return False

    def list_api_keys(self, user_id: str = "") -> List[Dict]:
        keys = self.api_keys.values()
        if user_id:
            keys = [k for k in keys if k.user_id == user_id]
        return [
            {k: v for k, v in asdict(ak).items() if k != "key_hash"}
            for ak in keys
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ═══════════════════════════════════════════════════════════════════════════════

_manager: Optional[MultiTenantManager] = None


def get_rbac_manager() -> MultiTenantManager:
    global _manager
    if _manager is None:
        _manager = MultiTenantManager()
    return _manager
