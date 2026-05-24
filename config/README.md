# Runtime config directory

This directory is mounted into the Docker container as `/app/config`.

On first container start, `docker-entrypoint.sh` copies `/app/config.example.json` to:

```text
config/config.json
```

`config/config.json` contains real mailbox credentials and Microsoft Graph secrets, so it is intentionally ignored by Git.

You can also create it manually:

```bash
cp config.example.json config/config.json
chmod 600 config/config.json
```

## Microsoft Graph 字段对应关系

在 WebUI 的 Graph 配置中：

```text
Graph Tenant ID     = 目录(租户) ID
Graph Client ID     = 应用程序(客户端) ID
Graph Client Secret = 客户端密码的“值”
```

不要填写：

```text
对象 ID
客户端密码的“机密 ID”
```

注意：客户端密码的“值”通常只在创建时显示一次。如果已经离开页面没有复制，需要重新新建一个客户端密码。
