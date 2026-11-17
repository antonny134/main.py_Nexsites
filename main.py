import base64
import bcrypt
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles


ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("NEXSITES_DATA_DIR", ROOT_DIR / "data"))
SITES_FILE = DATA_DIR / "sites.json"
USERS_FILE = DATA_DIR / "users.json"
COMMENTS_FILE = DATA_DIR / "comments.json"
FOLLOWS_FILE = DATA_DIR / "follows.json"
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret").encode("utf-8")
TOKEN_LIFETIME_SECONDS = 8 * 60 * 60


def read_records(file_path: Path) -> list[dict[str, Any]]:
    if not file_path.exists():
        return []

    data = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if data == {}:
        return []
    raise ValueError(f"{file_path} precisa conter uma lista JSON")


def save_records(file_path: Path, records: list[dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary_file = file_path.with_suffix(file_path.suffix + ".tmp")
    temporary_file.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_file.replace(file_path)


DATA_DIR.mkdir(parents=True, exist_ok=True)
for data_file in (SITES_FILE, USERS_FILE, COMMENTS_FILE, FOLLOWS_FILE):
    if not data_file.exists():
        data_file.write_text("[]", encoding="utf-8")

database: list[dict[str, Any]] = read_records(SITES_FILE)
users: list[dict[str, Any]] = read_records(USERS_FILE)
comments: list[dict[str, Any]] = read_records(COMMENTS_FILE)
follows: list[dict[str, Any]] = read_records(FOLLOWS_FILE)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.exception_handler(StarletteHTTPException)
async def handle_http_error(_, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": message},
        headers=exc.headers,
    )


def encode_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_segment(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_token(username: str) -> str:
    issued_at = int(datetime.now(timezone.utc).timestamp())
    header = encode_segment(b'{"alg":"HS256","typ":"JWT"}')
    payload = encode_segment(
        json.dumps(
            {
                "username": username,
                "iat": issued_at,
                "exp": issued_at + TOKEN_LIFETIME_SECONDS,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signed_content = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(JWT_SECRET, signed_content, hashlib.sha256).digest()
    return f"{header}.{payload}.{encode_segment(signature)}"


def current_username(authorization: str | None = Header(default=None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing auth")

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(status_code=401, detail="invalid auth")

    try:
        header_segment, payload_segment, signature_segment = token.split(".")
        header = json.loads(decode_segment(header_segment))
        payload = json.loads(decode_segment(payload_segment))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("invalid token")
        signature = decode_segment(signature_segment)
        signed_content = f"{header_segment}.{payload_segment}".encode("ascii")
        expected_signature = hmac.new(
            JWT_SECRET,
            signed_content,
            hashlib.sha256,
        ).digest()
        username = payload.get("username") or payload.get("sub")
        expires_at = payload.get("exp")
        if (
            header.get("alg") != "HS256"
            or not hmac.compare_digest(signature, expected_signature)
            or not isinstance(username, str)
            or not username
            or not isinstance(expires_at, (int, float))
            or expires_at <= datetime.now(timezone.utc).timestamp()
        ):
            raise ValueError("invalid token")
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc

    return username


def find_site(site_id: str) -> dict[str, Any] | None:
    return next((site for site in database if str(site.get("id")) == site_id), None)


def persist_sites() -> None:
    save_records(SITES_FILE, database)


def persist_comments() -> None:
    save_records(COMMENTS_FILE, comments)


def persist_follows() -> None:
    save_records(FOLLOWS_FILE, follows)


def with_views(site: dict[str, Any]) -> dict[str, Any]:
    return {**site, "views": site.get("views", 0)}


def newest_first(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(sites, key=lambda site: str(site.get("createdAt", "")), reverse=True)


def clean_text(value: Any, max_length: int) -> str:
    return str(value or "").strip()[:max_length]


def clean_tags(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    tags: list[str] = []
    for item in value:
        tag = clean_text(item, 20).lower().lstrip("#")
        if tag and tag not in tags:
            tags.append(tag)
    return tags[:5]


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT_DIR / "index.html")


@app.post("/api/register")
def register(account: dict[str, Any]) -> dict[str, bool]:
    username = account.get("username")
    password = account.get("password")
    if not isinstance(username, str) or not username.strip():
        raise HTTPException(status_code=400, detail="username required")
    if not isinstance(password, str) or not password:
        raise HTTPException(status_code=400, detail="password required")
    username = username.strip()
    if any(
        str(user.get("username", "")).lower() == username.lower() for user in users
    ):
        raise HTTPException(status_code=400, detail="user exists")

    password_hash = bcrypt.hashpw(
        password.encode("utf-8")[:72],
        bcrypt.gensalt(rounds=12),
    ).decode("ascii")
    users.append(
        {
            "username": username,
            "passwordHash": password_hash,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
    )
    save_records(USERS_FILE, users)
    return {"ok": True}


@app.post("/api/login")
def login(credentials: dict[str, Any]) -> dict[str, str]:
    username = credentials.get("username")
    password = credentials.get("password")
    if not isinstance(username, str) or not username:
        raise HTTPException(status_code=400, detail="username and password required")
    if not isinstance(password, str) or not password:
        raise HTTPException(status_code=400, detail="username and password required")

    user = next((item for item in users if item.get("username") == username), None)
    if not user:
        raise HTTPException(status_code=400, detail="invalid credentials")

    stored_hash = user.get("passwordHash", "")
    try:
        valid_password = bcrypt.checkpw(
            password.encode("utf-8")[:72],
            stored_hash.encode("ascii"),
        )
    except (ValueError, TypeError):
        valid_password = False
    if not valid_password:
        raise HTTPException(status_code=400, detail="invalid credentials")

    return {"token": create_token(username)}


@app.get("/api/users")
def list_users() -> list[str]:
    """Nomes de todas as pessoas cadastradas (nunca expõe senhas/hashes)."""
    return [str(user["username"]) for user in users if user.get("username")]


@app.get("/api/sites")
def list_sites() -> list[dict[str, Any]]:
    """Tudo que todo mundo postou, do mais recente para o mais antigo."""
    return [with_views(site) for site in newest_first(database)]


@app.post("/api/sites")
def create_site(
    site_data: dict[str, Any],
    username: str = Depends(current_username),
) -> dict[str, Any]:
    nome = site_data.get("nome")
    url = site_data.get("url")
    if not isinstance(nome, str) or not nome.strip():
        raise HTTPException(status_code=400, detail="nome and url required")
    if not isinstance(url, str) or not url.strip():
        raise HTTPException(status_code=400, detail="nome and url required")

    numeric_ids = [
        site["id"]
        for site in database
        if isinstance(site.get("id"), int) and not isinstance(site.get("id"), bool)
    ]
    site = {
        "id": max(numeric_ids, default=0) + 1,
        "nome": clean_text(nome, 50),
        "url": clean_text(url, 300),
        "descri": clean_text(site_data.get("descri"), 140),
        "categoria": clean_text(site_data.get("categoria"), 60),
        "idioma": clean_text(site_data.get("idioma"), 30),
        "detalhes": clean_text(site_data.get("detalhes"), 600),
        "repo": clean_text(site_data.get("repo"), 300),
        "tags": clean_tags(site_data.get("tags")),
        "owner": username,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "likes": 0,
        "dislikes": 0,
        "likedBy": [],
        "dislikedBy": [],
        "views": 0,
    }

    database.insert(0, site)
    persist_sites()
    return site


@app.delete("/api/sites/{site_id}")
def delete_site(
    site_id: str,
    username: str = Depends(current_username),
) -> dict[str, bool]:
    site = find_site(site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="site not found")
    if site.get("owner") != username:
        raise HTTPException(
            status_code=403,
            detail="only the site owner can delete it",
        )

    database.remove(site)
    comments[:] = [
        comment for comment in comments if str(comment.get("siteId")) != site_id
    ]
    persist_sites()
    persist_comments()
    return {"ok": True}


@app.get("/api/sites/search")
def search_sites(q: str = Query(default="")) -> list[dict[str, Any]]:
    query = q.lower().strip()
    matching_sites = [
        with_views(site)
        for site in newest_first(database)
        if query in str(site.get("nome", "")).lower()
        or query in str(site.get("descri", "")).lower()
        or query in str(site.get("categoria", "")).lower()
        or query in str(site.get("owner", "")).lower()
        or any(query in str(tag).lower() for tag in site.get("tags", []) or [])
    ]
    return matching_sites


@app.get("/api/sites/popular")
def popular_sites(limit: int | None = Query(default=None, ge=1)) -> list[dict[str, Any]]:
    sorted_sites = sorted(
        database,
        key=lambda site: site.get("likes", 0),
        reverse=True,
    )
    if limit is not None:
        sorted_sites = sorted_sites[:limit]
    return [with_views(site) for site in sorted_sites]


def change_reaction(site_id: str, username: str, reaction: str) -> dict[str, Any]:
    site = find_site(site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="site not found")

    liked_by = site.setdefault("likedBy", [])
    disliked_by = site.setdefault("dislikedBy", [])
    current_list = liked_by if reaction == "like" else disliked_by
    other_list = disliked_by if reaction == "like" else liked_by
    current_count = reaction + "s"
    other_reaction = "dislike" if reaction == "like" else "like"
    other_count = other_reaction + "s"

    if username in current_list:
        current_list.remove(username)
        site[current_count] = max(0, site.get(current_count, 0) - 1)
    else:
        current_list.append(username)
        site[current_count] = site.get(current_count, 0) + 1
        if username in other_list:
            other_list.remove(username)
            site[other_count] = max(0, site.get(other_count, 0) - 1)

    persist_sites()
    return site


@app.post("/api/sites/{site_id}/like")
def like_site(
    site_id: str,
    username: str = Depends(current_username),
) -> dict[str, Any]:
    return change_reaction(site_id, username, "like")


@app.post("/api/sites/{site_id}/dislike")
def dislike_site(
    site_id: str,
    username: str = Depends(current_username),
) -> dict[str, Any]:
    return change_reaction(site_id, username, "dislike")


@app.post("/api/sites/{site_id}/view")
def view_site(site_id: str) -> dict[str, Any]:
    site = find_site(site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="site not found")
    site["views"] = site.get("views", 0) + 1
    persist_sites()
    return {"ok": True, "id": site["id"], "views": site["views"]}


@app.get("/api/comments")
def list_comments() -> list[dict[str, Any]]:
    return comments


@app.post("/api/sites/{site_id}/comments")
def add_comment(
    site_id: str,
    comment_data: dict[str, Any],
    username: str = Depends(current_username),
) -> dict[str, Any]:
    site = find_site(site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="site not found")
    texto = comment_data.get("texto")
    if not isinstance(texto, str) or not texto.strip():
        raise HTTPException(status_code=400, detail="texto required")

    comment = {
        "id": f"com_{secrets.token_urlsafe(12)}",
        "siteId": site["id"],
        "author": username,
        "texto": texto.strip(),
        "resposta": None,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    comments.append(comment)
    persist_comments()
    return comment


@app.post("/api/comments/{comment_id}/reply")
def reply_to_comment(
    comment_id: str,
    reply_data: dict[str, Any],
    username: str = Depends(current_username),
) -> dict[str, Any]:
    comment = next(
        (item for item in comments if str(item.get("id")) == comment_id),
        None,
    )
    if comment is None:
        raise HTTPException(status_code=404, detail="comment not found")
    site = find_site(str(comment.get("siteId")))
    if site is None:
        raise HTTPException(status_code=404, detail="site not found")
    if site.get("owner") != username:
        raise HTTPException(
            status_code=403,
            detail="only the site owner can reply",
        )
    texto = reply_data.get("texto")
    if not isinstance(texto, str) or not texto.strip():
        raise HTTPException(status_code=400, detail="texto required")

    comment["resposta"] = {
        "texto": texto.strip(),
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    persist_comments()
    return comment


@app.get("/api/follows")
def list_follows() -> list[dict[str, Any]]:
    """Quem segue quem: [{seguidor, seguido, createdAt}]."""
    return follows


@app.post("/api/follows")
def set_follow(
    follow_data: dict[str, Any],
    username: str = Depends(current_username),
) -> dict[str, Any]:
    target = follow_data.get("seguido")
    if not isinstance(target, str) or not target.strip():
        raise HTTPException(status_code=400, detail="seguido required")
    target = target.strip()
    if target.lower() == username.lower():
        raise HTTPException(status_code=400, detail="cannot follow yourself")

    active = bool(follow_data.get("ativo", True))
    follows[:] = [
        item
        for item in follows
        if not (
            str(item.get("seguidor", "")).lower() == username.lower()
            and str(item.get("seguido", "")).lower() == target.lower()
        )
    ]
    if active:
        follows.append(
            {
                "seguidor": username,
                "seguido": target,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
        )
    persist_follows()
    return {"ok": True, "seguindo": active}


@app.get("/favicon.ico")
def favicon() -> JSONResponse:
    return JSONResponse(status_code=204, content=None)


if (ROOT_DIR / "img").is_dir():
    app.mount("/img", StaticFiles(directory=ROOT_DIR / "img"), name="images")


if __name__ == "__main__":
    uvicorn.run(app,host="127.0.0.1",port=int(os.environ.get("PORT", "8000")),)