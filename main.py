"""
Aitu Passport 电子签章 Demo
=============================

本demo演示如何使用Aitu Passport API实现电子签章功能。

流程:
1. 上传文档到Aitu Passport获取signableId
2. 生成OAuth2授权链接，用户点击后跳转到Aitu Passport进行签名
3. 用户签名完成后回调，获取授权码
4. 用授权码换取access_token
5. 使用token获取签名结果
"""

import base64
import secrets
import urllib.parse
from typing import Optional
from dataclasses import dataclass

import requests
from flask import Flask, request, redirect, jsonify, render_template


# ==================== 配置 ====================

@dataclass
class AituPassportConfig:
    """Aitu Passport 配置"""
    # 环境选择: "production" 或 "test"
    environment: str = "test"

    # OAuth2 客户端凭证 (从Aitu Passport控制台获取)
    client_id: str = "28388a7f-1f57-4f2b-9973-1c2de473a951"
    client_secret: str = "RcQlEWe4gbikvyr684ZG3odqgo4lTqmDhlhtJRuJHYkokti4Cjhqr5lqLx3qTeSW"

    # 回调地址 (需要在Aitu Passport控制台配置)
    redirect_uri: str = "https://anti.zoowayss.dpdns.org/callback"
    
    # 是否启用详细的请求日志
    verbose: bool = True

    @property
    def base_url(self) -> str:
        if self.environment == "production":
            return "https://passport.aitu.io"
        return "https://passport.test.supreme-team.tech"


# 全局配置实例
config = AituPassportConfig()

# Flask应用
app = Flask(__name__)

# 存储state用于验证回调 (生产环境应使用Redis等)
pending_states: dict[str, dict] = {}


# ==================== API客户端 ====================

class AituPassportClient:
    """Aitu Passport API 客户端"""

    def __init__(self, cfg: AituPassportConfig):
        self.config = cfg
        self.session = requests.Session()

    def _get_basic_auth(self) -> tuple[str, str]:
        """获取Basic Auth凭证"""
        return (self.config.client_id, self.config.client_secret)

    def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """
        统一的请求处理方法，添加详细的日志记录

        Args:
            method: HTTP方法 (GET, POST等)
            url: 请求URL
            **kwargs: 传递给requests的其他参数

        Returns:
            Response对象
        """
        if self.config.verbose:
            # 打印请求详情
            print(f"\n{'='*50}")
            print(f"=== Request Details ===")
            print(f"{'='*50}")
            print(f"Method: {method}")
            print(f"URL: {url}")
            print(f"Environment: {self.config.environment}")
            
            # 打印认证信息
            if 'auth' in kwargs:
                auth = kwargs['auth']
                if isinstance(auth, tuple) and len(auth) == 2:
                    print(f"Auth: Basic Auth")
                    print(f"Client ID: {auth[0]}")
                    # print(f"Client Secret: {'*' * 8}...{auth[1][-4:] if len(auth[1]) > 4 else '****'}")
                    print(f"Client Secret: {auth[1]}")
            
            if 'headers' in kwargs and 'Authorization' in kwargs['headers']:
                auth_header = kwargs['headers']['Authorization']
                if auth_header.startswith('Bearer '):
                    print(f"Auth: Bearer Token")
                    token = auth_header[7:]
                    print(f"Token: {token[:8]}...{token[-4:] if len(token) > 12 else '****'}")
            
            # 打印请求体信息
            if 'json' in kwargs:
                payload = kwargs['json']
                print(f"Content-Type: application/json")
                if 'bytes' in payload:
                    print(f"Request Body: {{")
                    print(f"  'name': '{payload.get('name', 'N/A')}'")
                    print(f"  'bytes': '<base64 data, {len(payload['bytes'])} chars>'")
                    if 'link' in payload:
                        print(f"  'link': '{payload['link']}'")
                    print(f"}}")
                elif 'link' in payload:
                    print(f"Request Body: {{")
                    print(f"  'name': '{payload.get('name', 'N/A')}'")
                    print(f"  'link': '{payload['link']}'")
                    print(f"}}")
                else:
                    print(f"Request Body: {payload}")
            elif 'data' in kwargs:
                print(f"Content-Type: application/x-www-form-urlencoded")
                print(f"Request Body: {kwargs['data']}")
        
        # 发送请求
        response = self.session.request(method, url, **kwargs)
        
        if self.config.verbose:
            # 打印响应详情
            print(f"\n{'='*50}")
            print(f"=== Response Details ===")
            print(f"{'='*50}")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            
            # 根据内容类型打印响应体
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                print(f"Response Body: {response.text}")
            elif 'image/' in content_type or 'video/' in content_type:
                print(f"Response Body: <二进制数据, {len(response.content)} bytes>")
            else:
                print(f"Response Body: {response.text[:500]}{'...' if len(response.text) > 500 else ''}")
            
            # 如果是403错误，打印诊断信息
            if response.status_code == 403:
                print(f"\n{'='*50}")
                print(f"=== 403 错误诊断 ===")
                print(f"{'='*50}")
                print(f"可能的原因:")
                print(f"1. Client ID 或 Client Secret 无效或已过期")
                print(f"2. 该客户端没有相应的权限（需要在 Aitu Passport 控制台启用）")
                print(f"3. IP 地址未在白名单中")
                print(f"4. 环境配置错误（当前: {self.config.environment}）")
                print(f"\n建议检查:")
                print(f"- 登录 Aitu Passport 控制台验证客户端凭证")
                print(f"- 确认客户端已启用所需功能")
                print(f"- 检查是否有 IP 白名单限制")
            
            print(f"{'='*50}\n")
        else:
            # 简洁模式：只打印一行日志
            print(f"{method} {url} -> {response.status_code}")
        
        return response

    def upload_document(self, file_path: str, file_name: Optional[str] = None) -> str:
        """
        上传文档用于签名

        Args:
            file_path: 文件路径
            file_name: 文件名 (可选，默认使用file_path的文件名)

        Returns:
            signableId: 文档ID，用于后续签名流程
        """
        if file_name is None:
            file_name = file_path.split("/")[-1]

        # 读取文件并转为base64
        with open(file_path, "rb") as f:
            file_bytes = base64.b64encode(f.read()).decode("utf-8")

        url = f"{self.config.base_url}/api/v2/oauth/signable"
        payload = {
            "bytes": file_bytes,
            "name": file_name
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        result = response.json()
        return result["signableId"]

    def upload_pdf_document(self, file_path: str, file_name: Optional[str] = None) -> str:
        """
        上传PDF文档用于签名 (签名将嵌入PDF文件)

        Args:
            file_path: PDF文件路径
            file_name: 文件名 (可选)

        Returns:
            signableId: 文档ID
        """
        if file_name is None:
            file_name = file_path.split("/")[-1]

        with open(file_path, "rb") as f:
            file_bytes = base64.b64encode(f.read()).decode("utf-8")

        url = f"{self.config.base_url}/api/v2/oauth/signable/pdf"
        payload = {
            "bytes": file_bytes,
            "name": file_name
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()["signableId"]

    def upload_document_by_url(self, file_url: str, file_name: Optional[str] = None) -> str:
        """
        通过URL上传文档用于签名

        Args:
            file_url: 文件URL (必须是https，或http://localhost)
            file_name: 文件名 (可选，默认从URL提取)

        Returns:
            signableId: 文档ID
        """
        if file_name is None:
            file_name = file_url.split("/")[-1].split("?")[0]

        url = f"{self.config.base_url}/api/v2/oauth/signable"
        payload = {
            "link": file_url,
            "name": file_name
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()["signableId"]

    def upload_pdf_by_url(self, file_url: str, file_name: Optional[str] = None) -> str:
        """
        通过URL上传PDF文档用于签名 (签名将嵌入PDF文件)

        Args:
            file_url: PDF文件URL (必须是https，或http://localhost)
            file_name: 文件名 (可选)

        Returns:
            signableId: 文档ID
        """
        if file_name is None:
            file_name = file_url.split("/")[-1].split("?")[0]
            if not file_name.lower().endswith(".pdf"):
                file_name = "document.pdf"

        url = f"{self.config.base_url}/api/v2/oauth/signable/pdf"
        payload = {
            "link": file_url,
            "name": file_name
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()["signableId"]

    def upload_xml_document(self, file_path: str, file_name: Optional[str] = None) -> str:
        """
        上传XML文档用于签名 (签名将嵌入XML文件)

        Args:
            file_path: XML文件路径
            file_name: 文件名 (可选)

        Returns:
            signableId: 文档ID
        """
        if file_name is None:
            file_name = file_path.split("/")[-1]

        with open(file_path, "rb") as f:
            file_bytes = base64.b64encode(f.read()).decode("utf-8")

        url = f"{self.config.base_url}/api/v2/oauth/signable/xml"
        payload = {
            "bytes": file_bytes,
            "name": file_name
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()["signableId"]

    def generate_auth_url(
        self,
        signable_ids: list[str],
        state: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        phone: Optional[str] = None,
        iin: Optional[str] = None,
        locale: str = "ru"
    ) -> tuple[str, str]:
        """
        生成OAuth2授权链接

        Args:
            signable_ids: 要签名的文档ID列表
            state: 状态参数 (可选，默认自动生成)
            scopes: 额外的scope (可选)
            phone: 预填手机号 (可选)
            iin: 预填IIN (可选)
            locale: 语言 (ru/kk/en/az/ky/tg/uz)

        Returns:
            (auth_url, state): 授权链接和state值
        """
        if state is None:
            state = secrets.token_urlsafe(16)

        # 构建scope
        base_scopes = ["openid"]
        if scopes:
            base_scopes.extend(scopes)

        # 添加签名scope: sign.1,2,3 格式
        sign_scope = f"sign.{','.join(signable_ids)}"
        base_scopes.append(sign_scope)

        scope_str = " ".join(base_scopes)

        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "state": state,
            "phone": phone,
            "iin": iin,
            "scope": scope_str,
            "locale": locale
        }

        if phone:
            params["phone"] = phone
        if iin:
            params["iin"] = iin

        auth_url = f"{self.config.base_url}/oauth2/auth?" + urllib.parse.urlencode(params)
        return auth_url, state

    def exchange_code_for_token(self, code: str) -> dict:
        """
        用授权码换取token

        Args:
            code: 授权码

        Returns:
            包含access_token, id_token等的响应
        """
        url = f"{self.config.base_url}/oauth2/token"

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri
        }

        response = self._make_request(
            "POST",
            url,
            data=data,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()

    def get_signatures(self, access_token: str) -> list[dict]:
        """
        获取签名结果

        Args:
            access_token: 访问令牌

        Returns:
            签名列表，每个包含signableId和signature
        """
        url = f"{self.config.base_url}/api/v2/oauth/signatures"

        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = self._make_request("GET", url, headers=headers)
        response.raise_for_status()

        return response.json()

    def get_signed_pdf(self, access_token: str, signable_id: str) -> bytes:
        """
        获取签名后的PDF文件

        Args:
            access_token: 访问令牌
            signable_id: 文档ID

        Returns:
            签名后的PDF二进制数据
        """
        url = f"{self.config.base_url}/api/v2/oauth/signable/pdf/{signable_id}"

        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = self._make_request("GET", url, headers=headers)
        response.raise_for_status()

        return response.content


# 全局客户端实例
client = AituPassportClient(config)


# ==================== Web路由 ====================

@app.route("/")
def index():
    """首页"""
    return render_template('index.html')


@app.route("/upload", methods=["POST"])
def upload_document():
    """上传文档"""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # 保存临时文件
    import tempfile
    import os

    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)

    try:
        # 根据文件类型选择上传方式
        if file.filename.lower().endswith(".pdf"):
            signable_id = client.upload_pdf_document(temp_path, file.filename)
        elif file.filename.lower().endswith(".xml"):
            signable_id = client.upload_xml_document(temp_path, file.filename)
        else:
            signable_id = client.upload_document(temp_path, file.filename)

        # 生成签名链接
        sign_url = f"https://anti.zoowayss.dpdns.org/sign?signable_id={signable_id}"

        return jsonify({
            "success": True,
            "signable_id": signable_id,
            "sign_url": sign_url,
            "message": f"文档上传成功，请访问 sign_url 发起签名"
        })
    except requests.RequestException as e:
        # 处理 HTTP 错误
        error_msg = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', error_msg)
            except:
                error_msg = f"HTTP {e.response.status_code}: {e.response.reason}"
        
        return jsonify({
            "success": False,
            "error": error_msg
        }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    finally:
        # 清理临时文件
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/upload-by-url", methods=["POST"])
def upload_document_by_url():
    """通过URL上传文档"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    file_url = data.get("url")
    if not file_url:
        return jsonify({"error": "url is required"}), 400

    file_name = data.get("name")
    file_type = data.get("type")  # 可选: "pdf", "xml", "general"

    try:
        # 根据文件类型或URL扩展名选择上传方式
        if file_type == "pdf" or (not file_type and file_url.lower().split("?")[0].endswith(".pdf")):
            signable_id = client.upload_pdf_by_url(file_url, file_name)
        else:
            signable_id = client.upload_document_by_url(file_url, file_name)

        # 生成签名链接
        sign_url = f"https://anti.zoowayss.dpdns.org/sign?signable_id={signable_id}"

        return jsonify({
            "success": True,
            "signable_id": signable_id,
            "sign_url": sign_url,
            "message": "文档上传成功，请访问 sign_url 发起签名"
        })
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/sign")
def initiate_signing():
    """发起签名流程"""
    signable_id = request.args.get("signable_id")
    if not signable_id:
        return jsonify({"error": "signable_id is required"}), 400

    # 支持多个文档签名，用逗号分隔
    signable_ids = signable_id.split(",")

    # 生成授权链接
    auth_url, state = client.generate_auth_url(
        signable_ids=signable_ids,
        scopes=["phone", "first_name", "last_name"],  # 可选：获取用户信息
        locale="ru"
    )

    # 保存state用于验证回调
    pending_states[state] = {
        "signable_ids": signable_ids
    }

    # 重定向到Aitu Passport
    return redirect(auth_url)


@app.route("/callback")
def oauth_callback():
    """OAuth2 回调处理"""
    # 检查错误
    error = request.args.get("error")
    if error:
        error_description = request.args.get("error_description", "Unknown error")
        return jsonify({
            "success": False,
            "error": error,
            "error_description": error_description
        }), 400

    # 获取授权码和state
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return jsonify({"error": "Missing code or state"}), 400

    # 验证state
    if state not in pending_states:
        return jsonify({"error": "Invalid state"}), 400

    state_data = pending_states.pop(state)

    try:
        # 用授权码换取token
        token_response = client.exchange_code_for_token(code)
        access_token = token_response.get("access_token")

        # 获取签名结果
        signatures = client.get_signatures(access_token)

        return jsonify({
            "success": True,
            "message": "签名成功",
            "signatures": signatures,
            "signable_ids": state_data["signable_ids"]
        })
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== 命令行使用示例 ====================

def is_url(source: str) -> bool:
    """判断输入是否为URL"""
    return source.startswith("http://") or source.startswith("https://")


def demo_sign_document(file_source: str):
    """
    命令行签名文档示例

    Args:
        file_source: 要签名的文件路径或URL
    """
    print(f"正在上传文档: {file_source}")

    # 1. 上传文档
    if is_url(file_source):
        # URL模式
        if file_source.lower().endswith(".pdf") or ".pdf?" in file_source.lower():
            signable_id = client.upload_pdf_by_url(file_source)
        else:
            signable_id = client.upload_document_by_url(file_source)
    else:
        # 本地文件模式
        if file_source.lower().endswith(".pdf"):
            signable_id = client.upload_pdf_document(file_source)
        else:
            signable_id = client.upload_document(file_source)

    print(f"文档上传成功，signableId: {signable_id}")

    # 2. 生成授权链接
    auth_url, state = client.generate_auth_url([signable_id],phone="7715251555",iin="990315312345")

    print(f"\n请在浏览器中打开以下链接进行签名:")
    print(auth_url)
    print(f"\n签名完成后会回调到: {config.redirect_uri}")

    return signable_id, auth_url


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # 命令行模式：签名指定文件或URL
        file_source = sys.argv[1]
        demo_sign_document(file_source)
    else:
        # Web服务模式
        print("=" * 50)
        print("Aitu Passport 电子签章 Demo")
        print("=" * 50)
        print(f"\n环境: {config.environment}")
        print(f"Base URL: {config.base_url}")
        print(f"\n请确保已配置以下信息:")
        print(f"  - client_id: {config.client_id}")
        print(f"  - client_secret: {'*' * 8 if config.client_secret != 'YOUR_CLIENT_SECRET' else '未配置'}")
        print(f"  - redirect_uri: {config.redirect_uri}")
        print(f"\n启动Web服务...")
        print(f"访问 http://localhost:8000 开始使用\n")

        app.run(host="0.0.0.0", port=8000, debug=True)
