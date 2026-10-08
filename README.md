<div align="center">

# 🛠️ CodeArts Daily

**CodeArts 每日福利领取 · PKCE + DPoP 登录 · 单文件青龙脚本 · 多账号**

<img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/%E9%9D%92%E9%BE%99%E9%9D%A2%E6%9D%BF-%E5%8D%95%E6%96%87%E4%BB%B6%E8%BF%90%E8%A1%8C-4EAA25?style=flat-square" />
<img src="https://img.shields.io/badge/%E5%A4%9A%E8%B4%A6%E5%8F%B7-%E6%8D%A2%E8%A1%8C%E6%88%96%20%26%20%E5%88%86%E9%9A%94-2088FF?style=flat-square" />
<img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" />

</div>

---

## ✨ 这是什么

CodeArts 每日福利领取：活动列表 → 领取 → 确认 → 回读验证，四个环节都通过才算成功，避免「已受理但没到账」。凭据到期前自动续期。

## 📦 文件说明

| 文件 | 作用 |
|---|---|
| `codearts_login.py` | PKCE + DPoP 网页登录，输出凭据 JSON |
| `codearts_daily.py` | 每日福利领取（多账号、自动续期） |

## 🔑 先获取 Token

```bash
pip install cryptography
python codearts_login.py
```

浏览器完成登录后，本地回调自动换回凭据，输出一行 JSON，粘贴进 `CODEARTS_CREDENTIALS`。端口不便时可加 `--paste` 手动粘贴回调地址。

## 🧩 环境变量（支持多账号）

> 多账号用 **换行** 或 **`&`** 分隔，两种可以混用。`|` 是单条账号内部的字段分隔符，备注里不要再写 `|`。

| 环境变量 | 单条格式 |
|---|---|
| `CODEARTS_CREDENTIALS` | 单行 JSON（推荐，含 refresh_token 与 DPoP 私钥）；或 `AK\|SK\|STS` 简写（不能自动续期，JSON 必须每条独占一行） |

## 🚀 青龙部署

1. 安装依赖：`pip install -r requirements.txt`
2. 把签到脚本上传到青龙（或把整个仓库放进脚本目录）。
3. 在「环境变量」里添加上面的变量，值按单条格式填写。
4. 新建定时任务，参考：

```cron
40 8 * * * python codearts_daily.py
```

## ⚙️ 常用参数

- `--preview`：只读活动列表，不发领取请求
- `--only 2`：只跑第 2 个账号
- `--no-notify`：关闭推送

## 📢 推送（可选）

支持 `PUSHPLUS_TOKEN`、`BARK_URL`、`WECOM_WEBHOOK`、`DINGTALK_WEBHOOK`、`DINGTALK_SECRET`；青龙面板自带通知也会自动尝试。配了哪个用哪个，都没配就只打日志。

## ⚠️ 注意事项

- 登录回调指向 `127.0.0.1`：青龙在服务器上时，请在本地电脑跑登录工具，再把 JSON 填进面板。
- JSON 凭据包含 DPoP 私钥，请按密码级别保管。
- 简写 `AK|SK|STS` 不能自动续期，过期要重新获取。

## 🔒 安全

- 环境变量和运行期生成的 JSON 缓存都包含账号凭据，不要提交到公开仓库、不要外发。
- 仓库里的 `.gitignore` 已排除缓存文件；如果自己改过目录结构，请确认缓存文件没有被 `git add`。

## 📄 License

MIT © 2026 [L0NE-6](https://github.com/L0NE-6)
