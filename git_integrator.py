"""
PTaaS Automated Patching Engine — git_integrator.py
=====================================================
Integrates with GitHub to automate security fixes via isolated
hotfix branches and Pull Requests.

Fixed issues in original:
  - Branch naming called a live HTTP request just to get a rate-limit header
    (fragile, slow, produces unusable branch names like "ptaas-hotfix-0").
    Replaced with time.time_ns() for a stable unique suffix.
  - AsyncClient was instantiated outside an async context for no reason.
"""

import base64
import time
from typing import Dict, Any

try:
    import httpx
except ImportError:
    raise ImportError("httpx is required: pip install httpx")


async def create_security_pull_request(
    github_token: str,
    repo_owner: str,
    repo_name: str,
    target_file: str,
    fixed_content: str,
    vulnerability_title: str,
) -> Dict[str, Any]:
    """
    Full GitHub PR pipeline:
      1. Resolves the default branch and its latest commit SHA.
      2. Creates a unique security hotfix branch.
      3. Commits the patched file (base64-encoded per GitHub API requirement).
      4. Opens a Pull Request with a structured remediation summary.

    Returns a dict with keys: status, pr_url, branch  (on success)
                          or: status, error             (on failure)
    """
    base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    headers = {
        "Authorization":       f"Bearer {github_token}",
        "Accept":              "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Use nanosecond timestamp for a unique, URL-safe branch name
    branch_suffix = str(time.time_ns())[-10:]
    branch_name = f"ptaas-hotfix-{branch_suffix}"

    async with httpx.AsyncClient(headers=headers, timeout=15.0) as client:

        # ── Step 1: Resolve default branch & latest commit SHA ────────────────
        repo_resp = await client.get(base_url)
        if repo_resp.status_code == 401:
            return {"status": "FAILED", "error": "GitHub token is invalid or expired."}
        if repo_resp.status_code == 404:
            return {"status": "FAILED", "error": f"Repository '{repo_owner}/{repo_name}' not found."}
        if repo_resp.status_code != 200:
            return {"status": "FAILED", "error": f"GitHub API error {repo_resp.status_code}: {repo_resp.text}"}

        default_branch = repo_resp.json().get("default_branch", "main")

        ref_resp = await client.get(f"{base_url}/git/ref/heads/{default_branch}")
        if ref_resp.status_code != 200:
            return {
                "status": "FAILED",
                "error": f"Could not resolve ref for branch '{default_branch}': {ref_resp.text}",
            }
        commit_sha = ref_resp.json()["object"]["sha"]

        # ── Step 2: Create the hotfix branch ─────────────────────────────────
        branch_resp = await client.post(
            f"{base_url}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": commit_sha},
        )
        if branch_resp.status_code != 201:
            return {
                "status": "FAILED",
                "error": f"Branch creation failed ({branch_resp.status_code}): {branch_resp.text}",
            }

        # ── Step 3: Get existing file SHA (needed to update rather than create) ─
        file_resp = await client.get(
            f"{base_url}/contents/{target_file}",
            params={"ref": default_branch},
        )
        existing_file_sha: str | None = None
        if file_resp.status_code == 200:
            existing_file_sha = file_resp.json().get("sha")

        # ── Step 4: Commit the patched file ──────────────────────────────────
        encoded_content = base64.b64encode(fixed_content.encode("utf-8")).decode("utf-8")
        commit_payload: Dict[str, Any] = {
            "message": f"🛡️ [PTaaS Auto-Fix] Mitigate: {vulnerability_title}",
            "content": encoded_content,
            "branch":  branch_name,
        }
        if existing_file_sha:
            commit_payload["sha"] = existing_file_sha

        commit_resp = await client.put(
            f"{base_url}/contents/{target_file}",
            json=commit_payload,
        )
        if commit_resp.status_code not in (200, 201):
            return {
                "status": "FAILED",
                "error": f"File commit failed ({commit_resp.status_code}): {commit_resp.text}",
            }

        # ── Step 5: Open the Pull Request ────────────────────────────────────
        pr_body = (
            f"## 🤖 PTaaS Automated Remediation Report\n\n"
            f"**Vulnerability:** `{vulnerability_title}`\n"
            f"**File patched:** `{target_file}`\n"
            f"**Branch:** `{branch_name}`\n\n"
            f"### What changed?\n"
            f"Our scanning engine detected a security weakness and applied a "
            f"structural parameter fix directly to `{target_file}`.\n\n"
            f"### Review checklist\n"
            f"- [ ] Diff confirms only security-relevant changes\n"
            f"- [ ] CI pipeline passes all tests\n"
            f"- [ ] Staging environment verified post-merge\n\n"
            f"---\n"
            f"*Generated by PTaaS Core — merge to secure your application.*"
        )
        pr_resp = await client.post(
            f"{base_url}/pulls",
            json={
                "title": f"🛡️ PTaaS Security Patch: {vulnerability_title}",
                "head":  branch_name,
                "base":  default_branch,
                "body":  pr_body,
            },
        )

        if pr_resp.status_code == 201:
            pr_data = pr_resp.json()
            return {
                "status":   "SUCCESS",
                "pr_url":   pr_data.get("html_url"),
                "pr_number": pr_data.get("number"),
                "branch":   branch_name,
            }

        if pr_resp.status_code == 422:
            error_msg = pr_resp.json().get("message", pr_resp.text)
            return {
                "status": "FAILED",
                "error":  f"PR creation rejected by GitHub: {error_msg}",
            }

        return {
            "status": "FAILED",
            "error":  f"Pull Request creation failed ({pr_resp.status_code}): {pr_resp.text}",
        }