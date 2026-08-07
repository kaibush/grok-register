# -*- coding: utf-8 -*-
"""面向对象的 Grok2API 管理端客户端。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from curl_cffi import CurlMime, requests


class Grok2APIImportError(RuntimeError):
    """远程 Grok2API 登录或导入失败。"""


class Grok2APIClient:
    """封装管理员登录、令牌复用、multipart 上传与 SSE 结果解析。"""

    LOGIN_PATH = "/api/admin/v1/auth/login"
    IMPORT_PATH = "/api/admin/v1/accounts/import"
    CONFIG_KEYS = (
        "grok2api_remote_url",
        "grok2api_remote_username",
        "grok2api_remote_password",
    )

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        session: Any = None,
        login_timeout: float = 20,
        import_timeout: float = 120,
    ) -> None:
        self.base_url = self._normalize_base_url(base_url)
        self.username = str(username or "").strip()
        self.password = str(password or "")
        if not self.username or not self.password:
            raise Grok2APIImportError("Grok2API 管理员账号或密码为空")
        self.login_timeout = float(login_timeout)
        self.import_timeout = float(import_timeout)
        self._owns_session = session is None
        # Grok2API 是独立管理服务，不继承项目代理或环境代理。
        self.session = session or requests.Session(trust_env=False)
        self._access_token = ""

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        *,
        session: Any = None,
        login_timeout: float = 20,
        import_timeout: float = 120,
    ) -> "Grok2APIClient":
        """从项目配置创建客户端，并统一校验必填字段。"""
        if not cls.is_configured(config):
            raise Grok2APIImportError(
                "请先完整配置 Grok2API API 地址、管理员账号和密码"
            )
        return cls(
            str(config.get("grok2api_remote_url") or ""),
            str(config.get("grok2api_remote_username") or ""),
            str(config.get("grok2api_remote_password") or ""),
            session=session,
            login_timeout=login_timeout,
            import_timeout=import_timeout,
        )

    @classmethod
    def is_configured(cls, config: Mapping[str, Any]) -> bool:
        return all(str(config.get(key, "") or "").strip() for key in cls.CONFIG_KEYS)

    @property
    def access_token(self) -> str:
        """只读暴露当前会话令牌，便于诊断是否已登录。"""
        return self._access_token

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        base = str(value or "").strip().rstrip("/")
        if not base:
            raise Grok2APIImportError("Grok2API API 地址为空")
        if not base.startswith(("http://", "https://")):
            raise Grok2APIImportError(
                "Grok2API API 地址必须以 http:// 或 https:// 开头"
            )
        return base

    @staticmethod
    def _response_error(response: Any, fallback: str) -> str:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict) and error.get("message"):
                return str(error["message"])
            if payload.get("message"):
                return str(payload["message"])
        status = int(getattr(response, "status_code", 0) or 0)
        return f"{fallback} (HTTP {status})" if status else fallback

    @staticmethod
    def _iter_sse_events(
        lines: Iterable[Any],
    ) -> Iterable[tuple[str, Dict[str, Any]]]:
        event = "message"
        data_lines: list[str] = []
        for raw in lines:
            line = (
                raw.decode("utf-8", errors="replace")
                if isinstance(raw, bytes)
                else str(raw or "")
            ).rstrip("\r\n")
            if not line:
                if data_lines:
                    yield event, Grok2APIClient._decode_sse_data(data_lines)
                event, data_lines = "message", []
                continue
            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                event = line[6:].strip() or "message"
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        if data_lines:
            yield event, Grok2APIClient._decode_sse_data(data_lines)

    @staticmethod
    def _decode_sse_data(data_lines: Iterable[str]) -> Dict[str, Any]:
        raw_data = "\n".join(data_lines)
        try:
            payload = json.loads(raw_data)
        except json.JSONDecodeError:
            payload = {"message": raw_data}
        return payload if isinstance(payload, dict) else {"data": payload}

    @staticmethod
    def _load_auth_document(file_path: str | Path) -> tuple[Path, bytes]:
        path = Path(file_path).expanduser().resolve()
        if not path.is_file():
            raise Grok2APIImportError("Grok2API 授权 JSON 文件不存在")
        try:
            content = path.read_bytes()
            json.loads(content.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise Grok2APIImportError(f"Grok2API 授权 JSON 无效: {exc}") from exc
        return path, content

    def login(self, *, force: bool = False) -> str:
        """使用管理员账号密码登录；同一实例默认复用已取得的令牌。"""
        if self._access_token and not force:
            return self._access_token
        try:
            response = self.session.post(
                f"{self.base_url}{self.LOGIN_PATH}",
                json={"username": self.username, "password": self.password},
                headers={"Accept": "application/json"},
                timeout=self.login_timeout,
            )
        except Exception as exc:
            raise Grok2APIImportError(f"连接 Grok2API 登录接口失败: {exc}") from exc
        if int(getattr(response, "status_code", 0) or 0) != 200:
            raise Grok2APIImportError(self._response_error(response, "Grok2API 登录失败"))
        try:
            payload = response.json()
            token = str(payload["data"]["tokens"]["accessToken"] or "").strip()
        except (KeyError, TypeError, ValueError) as exc:
            raise Grok2APIImportError("Grok2API 登录响应缺少 accessToken") from exc
        if not token:
            raise Grok2APIImportError("Grok2API 登录响应缺少 accessToken")
        self._access_token = token
        return token

    def import_auth_file(self, file_path: str | Path) -> Dict[str, Any]:
        """自动登录并将一个 grok_build JSON 导入远程管理端。"""
        path, content = self._load_auth_document(file_path)
        token = self.login()
        multipart = CurlMime()
        multipart.addpart(
            name="files",
            filename=path.name,
            content_type="application/json",
            data=content,
        )
        response = None
        try:
            request_kwargs = {
                "headers": {
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {token}",
                    "Cache-Control": "no-cache",
                },
                "multipart": multipart,
                "timeout": self.import_timeout,
                "stream": True,
            }
            try:
                response = self.session.post(
                    f"{self.base_url}{self.IMPORT_PATH}", **request_kwargs
                )
            except TypeError as exc:
                if "multipart" not in str(exc):
                    raise
                request_kwargs.pop("multipart", None)
                request_kwargs["files"] = {
                    "files": (path.name, content, "application/json")
                }
                response = self.session.post(
                    f"{self.base_url}{self.IMPORT_PATH}", **request_kwargs
                )
        except Exception as exc:
            raise Grok2APIImportError(f"连接 Grok2API 导入接口失败: {exc}") from exc
        finally:
            if response is None:
                multipart.close()

        try:
            if int(getattr(response, "status_code", 0) or 0) != 200:
                raise Grok2APIImportError(
                    self._response_error(response, "Grok2API 导入失败")
                )
            completed: Dict[str, Any] | None = None
            for event, payload in self._iter_sse_events(response.iter_lines()):
                if event == "error":
                    raise Grok2APIImportError(
                        str(
                            payload.get("message")
                            or payload.get("code")
                            or "Grok2API 导入失败"
                        )
                    )
                if event == "complete":
                    completed = payload
            if completed is None:
                raise Grok2APIImportError(
                    "Grok2API 导入响应未返回 complete 事件"
                )
            return completed
        finally:
            try:
                response.close()
            except Exception:
                pass
            multipart.close()

    def close(self) -> None:
        """释放客户端自行创建的 HTTP 会话。"""
        if not self._owns_session:
            return
        try:
            self.session.close()
        except Exception:
            pass

    def __enter__(self) -> "Grok2APIClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
