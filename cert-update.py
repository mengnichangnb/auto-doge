from hashlib import sha1
import json
import hmac
import requests
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

api_endpoint = 'https://api.dogecloud.com'

# 从环境变量获取敏感信息
access_key = os.environ.get('ACCESS_KEY')
secret_key = os.environ.get('SECRET_KEY')

# 证书直链配置
cert_url = os.environ.get('CERT_URL')
private_key_url = os.environ.get('PRIVATE_KEY_URL')

def sign(signStr):
    """生成API签名"""
    signed_data = hmac.new(secret_key.encode(), signStr.encode('utf-8'), sha1)
    sign = signed_data.digest().hex()
    access_token = access_key + ":" + sign
    return access_token

def load_domains():
    """从domains.txt加载要绑定的域名"""
    domain_file = 'domains.txt'
    try:
        with open(domain_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        raise Exception(f"域名配置文件 {domain_file} 不存在")
    
    # 过滤空行和注释（以#开头的行）
    domains = [d for d in domains if d and not d.startswith('#')]
    
    if not domains:
        raise Exception(f"域名配置文件 {domain_file} 中没有有效域名")
    
    return domains

def download_file(url):
    """通过直链下载文件内容"""
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f'下载文件失败，状态码: {response.status_code}')
    return response.text

def get_cert_list():
    """获取远程证书列表"""
    path = '/cdn/cert/list.json'
    token = sign(path + '\n')
    headers = {'Authorization': f'TOKEN {token}'}
    response = requests.get(api_endpoint + path, headers=headers)

    if not response.ok:
        raise Exception(f'服务器错误: {response.status_code}')
    json_data = response.json()

    if json_data['code'] != 200:
        raise Exception(f'API请求错误: {json_data}')
    
    return json_data['data']['certs']

def upload_cert(name, cert, private_key):
    """上传新证书"""
    path = '/cdn/cert/upload.json'
    data = {
        'note': name,
        'cert': cert,
        'private': private_key,
    }
    post_data = json.dumps(data, separators=(',', ':'))
    token = sign(path + '\n' + post_data)
    headers = {
        'Authorization': f'TOKEN {token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(api_endpoint + path,
                    headers=headers,
                    data=post_data)
    if not response.ok:
        raise Exception(f'上传失败，状态码: {response.status_code}')
    json_data = response.json()
    if json_data['code'] != 200:
        raise Exception(f'上传错误: {json_data}')
    return json_data['data']['id']

def apply_cert(cert_id, domain):
    """应用证书到域名"""
    path = '/cdn/cert/bind.json'
    data = {
        'id': cert_id,
        'domain': domain,
    }
    post_data = json.dumps(data, separators=(',', ':'))
    token = sign(path + '\n' + post_data)
    headers = {
        'Authorization': f'TOKEN {token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(api_endpoint + path,
                    headers=headers,
                    data=post_data)
    if not response.ok:
        raise Exception(f'绑定失败，状态码: {response.status_code}')
    json_data = response.json()
    if json_data['code'] != 200:
        raise Exception(f'绑定错误: {json_data}')
    return True

def get_cert_data(cert_data):
    """解析证书信息"""
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError:
        raise Exception("证书格式解析失败，请确保证书为有效的PEM格式")

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    common_name = cert.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME)[0].value
    return {
        'issue': int(not_before.timestamp()),
        'expire': int(not_after.timestamp()),
        'issue_date': not_before.strftime('%Y%m%d'),
        'name': common_name,
    }

if __name__ == '__main__':
    try:
        # 下载证书和私钥
        cert_content = download_file(cert_url)
        private_key_content = download_file(private_key_url)
        
        # 解析证书信息
        local_cert = get_cert_data(cert_content.encode('utf-8'))
        print(f'[INFO] 本地证书信息: {local_cert}')

        # 获取要绑定的域名
        apply_domains = load_domains()
        print(f'[INFO] 需要绑定的域名列表: {apply_domains}')

        # 获取远程证书列表
        remote_certs = get_cert_list()
        print(f'[INFO] 发现 {len(remote_certs)} 个远程证书')

        # 检查证书是否已存在
        for cert in remote_certs:
            if cert['name'] == local_cert['name']:
                if cert['issue'] == local_cert['issue'] and cert['expire'] == local_cert['expire']:
                    print(f'[INFO] 证书已存在，远程名称: {cert["note"]}')
                    print('[INFO] 无需更新，程序退出')
                    exit(0)

        # 上传新证书
        print('[INFO] 开始上传新证书')
        new_cert_name = f'{local_cert["name"]} {local_cert["issue_date"]}'
        new_cert_id = upload_cert(new_cert_name, cert_content, private_key_content)
        print(f'[INFO] 证书上传成功 | 名称: {new_cert_name} | ID: {new_cert_id}')

        # 应用证书到域名
        print('[INFO] 开始绑定证书到域名')
        for domain in apply_domains:
            print(f'[PROCESS] 正在绑定: {domain}')
            apply_cert(new_cert_id, domain)
            print(f'[SUCCESS] 已成功绑定: {domain}')
        
        print('[INFO] 所有操作已完成')

    except Exception as e:
        print(f'[ERROR] 程序执行出错: {str(e)}')
        exit(1)
