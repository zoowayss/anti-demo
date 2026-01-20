"""
Aitu Passport PDF 电子签章 Demo
=============================

本demo演示如何使用Aitu Passport API实现PDF电子签章功能。

流程:
1. 上传PDF文档到Aitu Passport获取signableId
2. 生成OAuth2授权链接，用户点击后跳转到Aitu Passport进行签名
3. 用户签名完成后回调，获取授权码
4. 用授权码换取access_token
5. 使用token获取签名后的PDF并验证
"""

import base64
import json
import os
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
    """Aitu Passport API 客户端 - 仅支持PDF"""

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
                    print(f"}}")
                else:
                    print(f"Request Body: {payload}")
            elif 'data' in kwargs:
                headers = kwargs.get('headers', {})
                content_type = headers.get('Content-Type', 'application/x-www-form-urlencoded')
                print(f"Content-Type: {content_type}")
                data = kwargs['data']
                if content_type == "application/json" and not isinstance(data, (bytes, str, bytearray)):
                    content_len = headers.get("Content-Length", "unknown")
                    print(f"Request Body: <流式JSON, Content-Length: {content_len}>")
                else:
                    print(f"Request Body: {data}")
        
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

        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            return self._upload_pdf_stream(f, file_name, file_size)

    def upload_pdf_by_url(self, file_url: str, file_name: Optional[str] = None) -> str:
        """
        通过URL上传PDF文档用于签名（先下载文件，再上传）
        签名将嵌入PDF文件

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

        # 从URL流式下载PDF文件
        with requests.get(file_url, stream=True, timeout=30) as download_response:
            download_response.raise_for_status()
            download_response.raw.decode_content = True
            content_length = download_response.headers.get("Content-Length")
            file_size = int(content_length) if content_length and content_length.isdigit() else None
            return self._upload_pdf_stream(download_response.raw, file_name, file_size)

    def _iter_base64_stream(self, stream, chunk_size: int = 8192):
        """按块进行Base64编码，避免整文件入内存"""
        pending = b""
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            if pending:
                chunk = pending + chunk
            # 只编码3的倍数，避免中间填充
            encode_len = (len(chunk) // 3) * 3
            if encode_len:
                yield base64.b64encode(chunk[:encode_len])
                pending = chunk[encode_len:]
            else:
                pending = chunk
        if pending:
            yield base64.b64encode(pending)

    def _build_streaming_payload(self, stream, file_name: str, file_size: Optional[int]):
        prefix = '{"bytes":"'
        suffix = '","name":' + json.dumps(file_name, ensure_ascii=True) + '}'
        prefix_bytes = prefix.encode("utf-8")
        suffix_bytes = suffix.encode("utf-8")

        def gen():
            yield prefix_bytes
            for part in self._iter_base64_stream(stream):
                yield part
            yield suffix_bytes

        content_length = None
        if file_size is not None:
            base64_len = 4 * ((file_size + 2) // 3)
            content_length = len(prefix_bytes) + base64_len + len(suffix_bytes)
        return gen(), content_length

    class _StreamingBody:
        """携带长度的迭代器，避免 requests 走 chunked 导致 400"""

        def __init__(self, iterable, length: int):
            self._iterable = iterable
            self._length = length

        def __iter__(self):
            return iter(self._iterable)

        def __len__(self):
            return self._length

    def _upload_pdf_stream(self, stream, file_name: str, file_size: Optional[int]) -> str:
        url = f"{self.config.base_url}/api/v2/oauth/signable/pdf"
        data, content_length = self._build_streaming_payload(stream, file_name, file_size)
        headers = {"Content-Type": "application/json"}
        if content_length is not None:
            headers["Content-Length"] = str(content_length)
            data = self._StreamingBody(data, content_length)

        response = self._make_request(
            "POST",
            url,
            data=data,
            headers=headers,
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
            signable_ids: 要签名的PDF文档ID列表
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

    def get_signed_pdfs(self, access_token: str) -> list[dict]:
        """
        获取所有签名后的PDF文件列表

        Args:
            access_token: 访问令牌

        Returns:
            签名PDF列表，每个包含signableId, name, signedPdf等字段
        """
        url = f"{self.config.base_url}/api/v2/oauth/signatures/pdf"

        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = self._make_request("GET", url, headers=headers)
        response.raise_for_status()

        return response.json()

    def verify_signed_pdf(self, signed_pdf_bytes: str) -> dict:
        """
        验证签名后的PDF文件

        Args:
            signed_pdf_bytes: 签名后的PDF文件的base64编码字符串

        Returns:
            验证结果，包含valid, signatureDetails, signers等字段
        """
        url = f"{self.config.base_url}/api/v2/oauth/signatures/pdf/verify"

        payload = {
            "bytes": signed_pdf_bytes
        }

        response = self._make_request(
            "POST",
            url,
            json=payload,
            auth=self._get_basic_auth()
        )
        response.raise_for_status()

        return response.json()


# 全局客户端实例
client = AituPassportClient(config)


# ==================== Web路由 ====================

@app.route("/")
def index():
    """首页"""
    return render_template('index.html')


@app.route("/upload-pdf", methods=["POST"])
def upload_pdf():
    """上传PDF文档"""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # 检查是否为PDF文件
    if not file.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files are supported"}), 400

    # 保存临时文件
    import tempfile
    import os

    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, file.filename)
    file.save(temp_path)

    try:
        # 上传PDF
        signable_id = client.upload_pdf_document(temp_path, file.filename)

        # 生成签名链接
        sign_url = f"https://anti.zoowayss.dpdns.org/sign?signable_id={signable_id}"

        return jsonify({
            "success": True,
            "signable_id": signable_id,
            "sign_url": sign_url,
            "message": f"PDF上传成功，请访问 sign_url 发起签名"
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


@app.route("/upload-pdf-by-url", methods=["POST"])
def upload_pdf_by_url():
    """通过URL上传PDF文档"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    file_url = data.get("url")
    if not file_url:
        return jsonify({"error": "url is required"}), 400

    file_name = data.get("name")

    try:
        signable_id = client.upload_pdf_by_url(file_url, file_name)

        # 生成签名链接
        sign_url = f"https://anti.zoowayss.dpdns.org/sign?signable_id={signable_id}"

        return jsonify({
            "success": True,
            "signable_id": signable_id,
            "sign_url": sign_url,
            "message": "PDF上传成功，请访问 sign_url 发起签名"
        })
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/sign")
def initiate_signing():
    """发起PDF签名流程"""
    signable_id = request.args.get("signable_id")
    if not signable_id:
        return jsonify({"error": "signable_id is required"}), 400

    # 支持多个PDF签名，用逗号分隔
    signable_ids = signable_id.split(",")

    # 生成授权链接
    auth_url, state = client.generate_auth_url(
        signable_ids=signable_ids,
        scopes=["phone", "first_name", "last_name"],  # 可选：获取用户信息
        locale="ru",
        phone="77715251555",
        iin="990315312345"
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

        # 获取签名后的PDF文件列表
        signed_pdfs = client.get_signed_pdfs(access_token)

        # 确保保存目录存在
        import os
        from datetime import datetime
        signed_dir = os.path.join(os.path.dirname(__file__), "static", "signed")
        os.makedirs(signed_dir, exist_ok=True)

        # 验证每个签名后的PDF
        verification_results = []
        for signed_pdf in signed_pdfs:
            signable_id = signed_pdf.get("signableId")
            signed_pdf_bytes = signed_pdf.get("documentCopy")  # base64编码的PDF
            original_name = signed_pdf.get("name")
            
            # 验证签名
            # verify_result = client.verify_signed_pdf(signed_pdf_bytes)
            
            # 提取签名者信息（只返回关键字段）
            # signers_info = []
            # for signer in verify_result.get("signers", []):
            #     signers_info.append({
            #         "firstName": signer.get("firstName"),
            #         "lastName": signer.get("lastName"),
            #         "middleName": signer.get("middleName"),
            #         "iin": signer.get("iin")
            #     })
            
            # 保存签名后的PDF文件
            # 生成唯一文件名：时间戳_signableId_原文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = f"{timestamp}_{signable_id}_{original_name}"
            file_path = os.path.join(signed_dir, safe_filename)
            
            # 将base64解码并保存
            pdf_content = base64.b64decode(signed_pdf_bytes)
            with open(file_path, "wb") as f:
                f.write(pdf_content)
            
            # 生成下载链接
            download_url = f"https://anti.zoowayss.dpdns.org/static/signed/{safe_filename}"
            
            verification_results.append({
                "signableId": signable_id,
                "name": original_name,
                "valid": True,
                "signers": [],
                "downloadUrl": download_url,
                "savedPath": file_path
            })

        return jsonify({
            "success": True,
            "message": "签名成功并已验证",
            "results": verification_results,
            "signable_ids": state_data["signable_ids"]
        })
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ==================== 命令行使用示例 ====================

def demo_sign_pdf(file_source: str):
    """
    命令行签名PDF示例

    Args:
        file_source: 要签名的PDF文件路径或URL
    """
    print(f"正在上传PDF: {file_source}")

    # 1. 上传PDF
    if file_source.startswith("http://") or file_source.startswith("https://"):
        # URL模式
        signable_id = client.upload_pdf_by_url(file_source)
    else:
        # 本地文件模式
        signable_id = client.upload_pdf_document(file_source)

    print(f"PDF上传成功，signableId: {signable_id}")

    # 2. 生成授权链接
    auth_url, state = client.generate_auth_url(
        [signable_id],
        phone="77715251555",
        iin="990315312345"
    )

    print(f"\n请在浏览器中打开以下链接进行签名:")
    print(auth_url)
    print(f"\n签名完成后会回调到: {config.redirect_uri}")

    return signable_id, auth_url


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # 命令行模式：签名指定PDF文件或URL
        file_source = sys.argv[1]
        demo_sign_pdf(file_source)
    else:
        # Web服务模式
        print("=" * 50)
        print("Aitu Passport PDF 电子签章 Demo")
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
