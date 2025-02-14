# 自动证书更新工具

## 功能说明
通过GitHub Actions自动更新DogeCloud CDN证书

## 配置要求
- 需配置的Secrets：
  - ACCESS_KEY: DogeCloud API密钥
  - SECRET_KEY: DogeCloud API密钥
  - CERT_URL: 证书PEM文件直链
  - PRIVATE_KEY_URL: 私钥PEM文件直链
  - APPLY_DOMAINS: 要绑定的域名（多个用逗号分隔）

## 运行机制
- 每天自动检查证书有效期
- 发现新证书时自动上传并绑定
- 支持手动触发工作流
