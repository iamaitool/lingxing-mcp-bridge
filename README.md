# 领星 MCP → ChatGPT 网页版

将 ChatGPT OAuth 连接转换为领星官方 MCP 的 `X-Mcp-Key` 鉴权。独立 Node.js 24 服务，无第三方运行时依赖，无数据库。

## 能力范围

提供经过明确允许的查询工具：Listing、FBA 库存与补货建议、产品表现、订单与 MSKU 利润、广告授权店铺及广告报表、关键词排名、竞品及跟卖监控、退货与买家之声。实际可用工具取决于领星账号权限及其 MCP 服务返回的工具清单。

所有未知工具与写操作均拒绝，包括修改竞价、价格、广告预算、删除货件。允许清单位于 `server.mjs` 的 `READ_TOOLS`，不要用宽泛的工具名称匹配替代。工具列表保留上游分页游标。

## Render 部署

使用独立 **Web Service / Node / Free**：

- Repository: `https://github.com/iamaitool/lingxing-mcp-bridge`
- Branch: `main`
- Build command: `npm ci --ignore-scripts && npm test`
- Start command: `npm start`
- 可选 Health check path: `/healthz`
- 环境变量来源：Render 服务的 Environment 页面。

| 环境变量 | 内容 |
|---|---|
| `NODE_VERSION` | `24.22.1` |
| `LINGXING_MCP_KEY` | 领星 AI助手 → MCP → 复制密钥 |
| `BRIDGE_PASSWORD` | 独立的中转登录密码，至少16字符；不要使用领星密钥或账号密码 |
| `TOKEN_SIGNING_KEY` | 至少32字符的高强度随机值，部署时生成；不要频繁更换 |
| `PUBLIC_URL` | 可选。自定义域名时填写 HTTPS 根地址；默认读取 Render 的 `RENDER_EXTERNAL_URL` |

`PORT` 由 Render 注入，监听 `0.0.0.0`。保存环境变量时选择 **Save and deploy**，不要只保存。缺少任何凭据时，服务仅开放状态页和 `/healthz`，数据与 OAuth 端点返回503。

Free 服务可能休眠，初次唤醒时连接可能超时，需要稍后重试。此项目不使用付费数据库、磁盘或后台任务；实际用量及免费额度以 Render 工作区为准。

## ChatGPT 中添加

部署并填写密钥后，在 ChatGPT「添加自定义 MCP 服务器」中：

- 名称：`领星 MCP`
- 描述：`查询领星商品、库存、销售、利润及广告报表`
- 服务器 URL：`https://你的服务地址/mcp`
- 身份验证：`OAuth`
- 高级 OAuth 设置通常保持自动发现；如果需要选择客户端配置，选择动态客户端注册（DCR）、公开客户端（none）。本服务不使用 client secret。

点击连接，在打开的授权页输入 `BRIDGE_PASSWORD`。不要在登录页输入领星密钥。授权后可提问「列出我的广告授权店铺」，再指定店铺和日期查询报表。

OAuth 使用授权码 + S256 PKCE；仅允许 ChatGPT 的正式 OAuth 回调地址。自动发现包含授权服务器元数据、资源元数据、DCR 和回调 issuer 校验。没有开放注册用户功能，授权始终需要服务所有者的密码。

## 会话与维护

- Access token 有效期 **12小时**。当前版本不发放 refresh token；到期后请在 ChatGPT 重新连接并登录。
- 重启不会使已签发的 access token 和注册客户端失效，只要域名、密码和签名密钥保持不变；登录表单使用15分钟有效的签名状态，能够跨实例重启继续提交；已签发但尚未兑换的授权码仍保存在内存，重启后需重新发起。
- 如需立即撤销所有授权，请更换 `TOKEN_SIGNING_KEY` 并部署，然后在 ChatGPT 删除并重新添加连接。
- 更换 `BRIDGE_PASSWORD` 只影响后续登录；不会撤销已签发的令牌。领星密钥在 Render 修改后部署生效。
- 不记录密码、请求正文、访问令牌、领星数据或上游响应正文。平台自身的访问日志与环境变量访问权限由 Render 管理。
- 此版本为单实例设计，登录状态和限流在内存中；不要直接扩展为多实例。

## 本地验证

```sh
npm ci --ignore-scripts
npm test
```

测试使用模拟领星服务，不访问真实业务数据。覆盖 PKCE、回调白名单、CSRF、密码校验、授权码单次使用、令牌受众与过期、只读工具拦截、上游独立会话及 SSE 响应解析。

## 故障排查

- 状态页提示等待配置：检查上述三个凭据的名称与长度，并保存部署。
- OAuth 回调失败：确认 URL 是根域名下的 `/mcp`，`PUBLIC_URL` 与实际域名一致，重新添加连接。
- 工具不可见：确认领星已经启用 MCP、账号有对应权限；返回列表只显示允许清单内的查询工具。
- 领星请求失败：检查密钥是否有效、账号是否具备权限，服务唤醒后重试。

## 官方参考

- [领星 MCP](https://www.lingxing.com/help/article/mcp)
- [ChatGPT MCP authentication](https://developers.openai.com/plugins/build/auth)
- [Render environment variables](https://render.com/docs/configure-environment-variables)
