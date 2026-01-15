# 使用 Python Alpine 基础镜像（最小体积）
FROM python:3.11-alpine

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装依赖（使用 --no-cache-dir 减少镜像体积）
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY main.py .
COPY templates/ templates/
COPY static/ static/

# 暴露端口
EXPOSE 8000

# 设置环境变量
ENV PYTHONUNBUFFERED=1

# 运行应用
CMD ["python", "main.py"]
