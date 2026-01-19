let selectedFile = null;

// 标签页切换
function switchTab(tabName) {
    // 隐藏所有标签页
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // 显示选中的标签页
    document.getElementById(tabName + '-tab').classList.add('active');
    event.target.classList.add('active');
}

// 拖拽上传
const uploadArea = document.getElementById('uploadArea');

uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('drag-over');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('drag-over');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        selectedFile = files[0];
        updateSelectedFile();
    }
});

// 文件选择
function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    updateSelectedFile();
}

function updateSelectedFile() {
    if (selectedFile) {
        document.getElementById('fileName').textContent = selectedFile.name;
        document.getElementById('selectedFile').classList.add('show');
        document.getElementById('uploadBtn').disabled = false;
    }
}

// 上传文件
async function uploadFile() {
    if (!selectedFile) return;
    
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    showLoading('upload');
    hideResult('upload');
    
    try {
        const response = await fetch('/upload-pdf', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        hideLoading('upload');
        
        if (data.success) {
            showResult('upload', 'success', `
                <h4>✅ 上传成功！</h4>
                <p><strong>文档ID：</strong> ${data.signable_id}</p>
                <p><a href="${data.sign_url}" target="_blank">点击此处开始签名 →</a></p>
            `);
        } else {
            showResult('upload', 'error', `
                <h4>❌ 上传失败</h4>
                <p>${data.error || '未知错误'}</p>
            `);
        }
    } catch (error) {
        hideLoading('upload');
        showResult('upload', 'error', `
            <h4>❌ 上传失败</h4>
            <p>${error.message}</p>
        `);
    }
}

// URL验证
function validateUrl() {
    const url = document.getElementById('urlInput').value.trim();
    const btn = document.getElementById('urlBtn');
    btn.disabled = !url || (!url.startsWith('http://') && !url.startsWith('https://'));
}

// 通过URL上传
async function uploadByUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;
    
    const fileType = document.querySelector('input[name="fileType"]:checked').value;
    
    const payload = {
        url: url
    };
    
    if (fileType !== 'auto') {
        payload.type = fileType;
    }
    
    showLoading('url');
    hideResult('url');
    
    try {
        const response = await fetch('/upload-by-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        hideLoading('url');
        
        if (data.success) {
            showResult('url', 'success', `
                <h4>✅ 上传成功！</h4>
                <p><strong>文档ID：</strong> ${data.signable_id}</p>
                <p><a href="${data.sign_url}" target="_blank">点击此处开始签名 →</a></p>
            `);
        } else {
            showResult('url', 'error', `
                <h4>❌ 上传失败</h4>
                <p>${data.error || '未知错误'}</p>
            `);
        }
    } catch (error) {
        hideLoading('url');
        showResult('url', 'error', `
            <h4>❌ 上传失败</h4>
            <p>${error.message}</p>
        `);
    }
}

// 显示/隐藏加载状态
function showLoading(type) {
    document.getElementById(type + 'Loading').style.display = 'block';
}

function hideLoading(type) {
    document.getElementById(type + 'Loading').style.display = 'none';
}

// 显示/隐藏结果
function showResult(type, status, html) {
    const result = document.getElementById(type + 'Result');
    result.className = 'result ' + status;
    result.innerHTML = html;
    result.style.display = 'block';
}

function hideResult(type) {
    document.getElementById(type + 'Result').style.display = 'none';
}
