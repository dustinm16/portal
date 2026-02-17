"""GitHub repository management plugin for Open Relay Portal."""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import aiohttp
from aiohttp import web, WSMsgType

from . import register_plugin
from .base import PluginBase, PluginInfo, ServiceTarget

logger = logging.getLogger("portal.plugins.github")


@dataclass
class GitHubSession:
    """Active GitHub session."""
    user_id: int
    access_token: str
    username: str
    repos: list = None


@register_plugin
class GitHubPlugin(PluginBase):
    """GitHub repository management plugin.

    Provides:
    - Repository listing and management
    - Clone/pull operations via terminal
    - Webhook management
    - Actions workflow triggering
    - Branch/PR management
    """

    info = PluginInfo(
        name="github",
        display_name="GitHub",
        description="GitHub repository management and CI/CD integration",
        version="1.0.0",
        icon="github",
        protocols=["websocket", "http"],
        config_schema={
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string",
                    "description": "GitHub OAuth App Client ID"
                },
                "client_secret": {
                    "type": "string",
                    "description": "GitHub OAuth App Client Secret"
                },
                "personal_token": {
                    "type": "string",
                    "description": "GitHub Personal Access Token (alternative to OAuth)"
                },
                "default_org": {
                    "type": "string",
                    "description": "Default organization to show repos from"
                },
                "webhook_secret": {
                    "type": "string",
                    "description": "Secret for validating webhooks"
                },
                "allowed_repos": {
                    "type": "string",
                    "description": "Comma-separated list of allowed repo patterns (e.g., 'myorg/*')"
                }
            }
        }
    )

    def __init__(self):
        super().__init__()
        self._sessions: dict[int, GitHubSession] = {}
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._oauth_states: dict[str, tuple[int, float]] = {}  # nonce -> (user_id, created_at)
        self._OAUTH_STATE_TTL = 900  # 15 minutes

    async def initialize(self) -> None:
        """Initialize HTTP session."""
        self._http_session = aiohttp.ClientSession()
        logger.info("GitHub plugin initialized")

    async def shutdown(self) -> None:
        """Clean up resources."""
        if self._http_session:
            await self._http_session.close()
        logger.info("GitHub plugin shutdown")

    async def _get_token(self, target: ServiceTarget, user_id: int) -> Optional[str]:
        """Get GitHub access token from config or session."""
        # Check for personal token in config
        if target.config.get("personal_token"):
            return target.config["personal_token"]

        # Check for user session token
        session = self._sessions.get(user_id)
        if session:
            return session.access_token

        return None

    async def _github_api(
        self,
        token: str,
        endpoint: str,
        method: str = "GET",
        data: dict = None
    ) -> tuple[int, dict]:
        """Make GitHub API request."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        url = f"https://api.github.com{endpoint}"

        try:
            async with self._http_session.request(
                method,
                url,
                headers=headers,
                json=data if data else None
            ) as resp:
                body = await resp.json() if resp.content_type == "application/json" else {}
                return resp.status, body
        except Exception as e:
            logger.error(f"GitHub API error: {e}")
            return 500, {"error": "GitHub API request failed"}

    async def handle_websocket(
        self,
        ws: web.WebSocketResponse,
        target: ServiceTarget,
        user_id: int
    ) -> None:
        """Handle WebSocket connection for GitHub operations."""
        logger.info(f"GitHub WebSocket connected for user {user_id}")

        token = await self._get_token(target, user_id)

        # Send initial state
        if token:
            # Verify token and get user info
            status, user_data = await self._github_api(token, "/user")
            if status == 200:
                await ws.send_json({
                    "type": "connected",
                    "user": user_data.get("login"),
                    "name": user_data.get("name"),
                    "avatar": user_data.get("avatar_url")
                })
            else:
                await ws.send_json({
                    "type": "error",
                    "message": "Invalid GitHub token"
                })
                return
        else:
            # Need authorization
            client_id = target.config.get("client_id")
            if client_id:
                # OAuth flow
                oauth_nonce = secrets.token_urlsafe(32)
                # Prune expired states to prevent unbounded memory growth
                now = time.time()
                self._oauth_states = {
                    k: v for k, v in self._oauth_states.items()
                    if now - v[1] < self._OAUTH_STATE_TTL
                }
                self._oauth_states[oauth_nonce] = (user_id, now)
                params = {
                    'client_id': client_id,
                    'scope': 'repo,read:user,workflow',
                    'state': oauth_nonce
                }
                auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
                await ws.send_json({
                    "type": "auth_required",
                    "auth_url": auth_url
                })
            else:
                await ws.send_json({
                    "type": "error",
                    "message": "GitHub not configured. Set personal_token or OAuth credentials."
                })
            return

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_command(ws, token, target, data, user_id)
                    except json.JSONDecodeError:
                        await ws.send_json({"type": "error", "message": "Invalid JSON"})
                elif msg.type == WSMsgType.CLOSE:
                    break
        except Exception as e:
            logger.error(f"GitHub WebSocket error: {e}")
        finally:
            self._sessions.pop(user_id, None)
            logger.info(f"GitHub WebSocket disconnected for user {user_id}")

    async def _handle_command(
        self,
        ws: web.WebSocketResponse,
        token: str,
        target: ServiceTarget,
        data: dict,
        user_id: int
    ) -> None:
        """Handle incoming WebSocket command."""
        cmd = data.get("command")

        if cmd == "disconnect":
            # Clear user's OAuth session
            if user_id in self._sessions:
                del self._sessions[user_id]
                logger.info(f"User {user_id} disconnected from GitHub")
            await ws.send_json({"type": "disconnected"})
        elif cmd == "list_repos":
            await self._list_repos(ws, token, data)
        elif cmd == "get_repo":
            await self._get_repo(ws, token, data)
        elif cmd == "list_branches":
            await self._list_branches(ws, token, data)
        elif cmd == "list_prs":
            await self._list_prs(ws, token, data)
        elif cmd == "list_workflows":
            await self._list_workflows(ws, token, data)
        elif cmd == "trigger_workflow":
            await self._trigger_workflow(ws, token, data)
        elif cmd == "list_runs":
            await self._list_workflow_runs(ws, token, data)
        elif cmd == "get_readme":
            await self._get_readme(ws, token, data)
        elif cmd == "create_repo":
            await self._create_repo(ws, token, data)
        else:
            await ws.send_json({"type": "error", "message": f"Unknown command: {cmd}"})

    async def _list_repos(self, ws, token: str, data: dict) -> None:
        """List user's repositories."""
        page = data.get("page", 1)
        per_page = data.get("per_page", 30)
        sort = data.get("sort", "updated")

        status, repos = await self._github_api(
            token,
            f"/user/repos?page={page}&per_page={per_page}&sort={sort}"
        )

        if status == 200:
            await ws.send_json({
                "type": "repos",
                "repos": [
                    {
                        "id": r["id"],
                        "name": r["name"],
                        "full_name": r["full_name"],
                        "description": r["description"],
                        "private": r["private"],
                        "html_url": r["html_url"],
                        "clone_url": r["clone_url"],
                        "ssh_url": r["ssh_url"],
                        "language": r["language"],
                        "stargazers_count": r["stargazers_count"],
                        "forks_count": r["forks_count"],
                        "updated_at": r["updated_at"],
                        "default_branch": r["default_branch"]
                    }
                    for r in repos
                ],
                "page": page
            })
        else:
            await ws.send_json({"type": "error", "message": repos.get("message", "Failed to list repos")})

    async def _get_repo(self, ws, token: str, data: dict) -> None:
        """Get repository details."""
        owner = data.get("owner")
        repo = data.get("repo")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        status, repo_data = await self._github_api(token, f"/repos/{owner}/{repo}")

        if status == 200:
            await ws.send_json({"type": "repo", "repo": repo_data})
        else:
            await ws.send_json({"type": "error", "message": repo_data.get("message", "Repo not found")})

    async def _list_branches(self, ws, token: str, data: dict) -> None:
        """List repository branches."""
        owner = data.get("owner")
        repo = data.get("repo")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        status, branches = await self._github_api(
            token,
            f"/repos/{owner}/{repo}/branches?per_page=100"
        )

        if status == 200:
            await ws.send_json({
                "type": "branches",
                "branches": [
                    {
                        "name": b["name"],
                        "protected": b["protected"],
                        "sha": b["commit"]["sha"]
                    }
                    for b in branches
                ]
            })
        else:
            await ws.send_json({"type": "error", "message": branches.get("message", "Failed to list branches")})

    async def _list_prs(self, ws, token: str, data: dict) -> None:
        """List pull requests."""
        owner = data.get("owner")
        repo = data.get("repo")
        state = data.get("state", "open")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        status, prs = await self._github_api(
            token,
            f"/repos/{owner}/{repo}/pulls?state={state}&per_page=30"
        )

        if status == 200:
            await ws.send_json({
                "type": "pull_requests",
                "pull_requests": [
                    {
                        "number": pr["number"],
                        "title": pr["title"],
                        "state": pr["state"],
                        "user": pr["user"]["login"],
                        "head": pr["head"]["ref"],
                        "base": pr["base"]["ref"],
                        "created_at": pr["created_at"],
                        "updated_at": pr["updated_at"],
                        "html_url": pr["html_url"],
                        "draft": pr.get("draft", False),
                        "mergeable": pr.get("mergeable")
                    }
                    for pr in prs
                ]
            })
        else:
            await ws.send_json({"type": "error", "message": prs.get("message", "Failed to list PRs")})

    async def _list_workflows(self, ws, token: str, data: dict) -> None:
        """List GitHub Actions workflows."""
        owner = data.get("owner")
        repo = data.get("repo")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        status, result = await self._github_api(
            token,
            f"/repos/{owner}/{repo}/actions/workflows"
        )

        if status == 200:
            await ws.send_json({
                "type": "workflows",
                "workflows": [
                    {
                        "id": w["id"],
                        "name": w["name"],
                        "path": w["path"],
                        "state": w["state"],
                        "badge_url": w["badge_url"]
                    }
                    for w in result.get("workflows", [])
                ]
            })
        else:
            await ws.send_json({"type": "error", "message": result.get("message", "Failed to list workflows")})

    async def _trigger_workflow(self, ws, token: str, data: dict) -> None:
        """Trigger a GitHub Actions workflow."""
        owner = data.get("owner")
        repo = data.get("repo")
        workflow_id = data.get("workflow_id")
        ref = data.get("ref", "main")
        inputs = data.get("inputs", {})

        if not owner or not repo or not workflow_id:
            await ws.send_json({"type": "error", "message": "owner, repo, and workflow_id required"})
            return

        status, result = await self._github_api(
            token,
            f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
            method="POST",
            data={"ref": ref, "inputs": inputs}
        )

        if status == 204:
            await ws.send_json({
                "type": "workflow_triggered",
                "message": f"Workflow triggered on {ref}"
            })
        else:
            await ws.send_json({"type": "error", "message": result.get("message", "Failed to trigger workflow")})

    async def _list_workflow_runs(self, ws, token: str, data: dict) -> None:
        """List workflow runs."""
        owner = data.get("owner")
        repo = data.get("repo")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        status, result = await self._github_api(
            token,
            f"/repos/{owner}/{repo}/actions/runs?per_page=20"
        )

        if status == 200:
            await ws.send_json({
                "type": "workflow_runs",
                "runs": [
                    {
                        "id": r["id"],
                        "name": r["name"],
                        "status": r["status"],
                        "conclusion": r["conclusion"],
                        "workflow_id": r["workflow_id"],
                        "head_branch": r["head_branch"],
                        "head_sha": r["head_sha"][:7],
                        "event": r["event"],
                        "created_at": r["created_at"],
                        "html_url": r["html_url"]
                    }
                    for r in result.get("workflow_runs", [])
                ]
            })
        else:
            await ws.send_json({"type": "error", "message": result.get("message", "Failed to list runs")})

    async def _get_readme(self, ws, token: str, data: dict) -> None:
        """Get repository README."""
        owner = data.get("owner")
        repo = data.get("repo")

        if not owner or not repo:
            await ws.send_json({"type": "error", "message": "owner and repo required"})
            return

        # Get README content
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        try:
            async with self._http_session.get(
                f"https://api.github.com/repos/{owner}/{repo}/readme",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    await ws.send_json({"type": "readme", "content": content})
                else:
                    await ws.send_json({"type": "readme", "content": "No README found"})
        except Exception as e:
            logger.error(f"GitHub README fetch error: {e}")
            await ws.send_json({"type": "error", "message": "Failed to fetch README"})

    async def _create_repo(self, ws, token: str, data: dict) -> None:
        """Create a new repository."""
        name = data.get("name")
        description = data.get("description", "")
        private = data.get("private", False)
        auto_init = data.get("auto_init", True)

        if not name:
            await ws.send_json({"type": "error", "message": "name required"})
            return

        status, result = await self._github_api(
            token,
            "/user/repos",
            method="POST",
            data={
                "name": name,
                "description": description,
                "private": private,
                "auto_init": auto_init
            }
        )

        if status == 201:
            await ws.send_json({
                "type": "repo_created",
                "repo": {
                    "name": result["name"],
                    "full_name": result["full_name"],
                    "html_url": result["html_url"],
                    "clone_url": result["clone_url"],
                    "ssh_url": result["ssh_url"]
                }
            })
        else:
            await ws.send_json({"type": "error", "message": result.get("message", "Failed to create repo")})

    async def handle_http(
        self,
        request: web.Request,
        target: ServiceTarget
    ) -> web.Response:
        """Handle HTTP requests (OAuth callback)."""
        # OAuth callback
        code = request.query.get("code")
        state = request.query.get("state")

        if code and state:
            # Exchange code for token
            client_id = target.config.get("client_id")
            client_secret = target.config.get("client_secret")

            if not client_id or not client_secret:
                return web.json_response({"error": "OAuth not configured"}, status=500)

            async with self._http_session.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code
                }
            ) as resp:
                token_data = await resp.json()

            if "access_token" in token_data:
                state_entry = self._oauth_states.pop(state, None)
                user_id = None
                if state_entry:
                    uid, created_at = state_entry
                    if time.time() - created_at < self._OAUTH_STATE_TTL:
                        user_id = uid
                if user_id is None:
                    return web.json_response({"error": "Invalid OAuth state"}, status=403)
                token = token_data["access_token"]

                # Get user info
                status, user_data = await self._github_api(token, "/user")
                if status == 200:
                    self._sessions[user_id] = GitHubSession(
                        user_id=user_id,
                        access_token=token,
                        username=user_data.get("login")
                    )

                    return web.Response(
                        text="<html><body><script>window.close();</script>Authorization successful! You can close this window.</body></html>",
                        content_type="text/html"
                    )

            return web.json_response({"error": "OAuth failed"}, status=400)

        return web.json_response({"error": "Invalid request"}, status=400)

    async def health_check(self, target: ServiceTarget) -> dict:
        """Check GitHub API availability."""
        try:
            async with self._http_session.get(
                "https://api.github.com/",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    return {"healthy": True, "message": "GitHub API reachable"}
                return {"healthy": False, "message": f"GitHub API returned {resp.status}"}
        except Exception as e:
            logger.warning(f"GitHub health check failed: {e}")
            return {"healthy": False, "message": "GitHub API unreachable"}
