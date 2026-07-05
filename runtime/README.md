# Runtime 目录

此目录存放运行时敏感数据，已被 `.gitignore` 排除，不会提交到公开仓库。

## 文件说明

| 文件 | 用途 |
|------|------|
| `tgbot.env` | Bot Token、管理员 ID（root 600） |
| `current-exit` | 当前出口名称 |
| `port-notes.json` | 防火墙端口备注 |

## 初始化

```bash
# 从示例创建 tgbot.env
cp deploy/tgbot.env.example runtime/tgbot.env
# 编辑填入真实 token
vi runtime/tgbot.env
chmod 600 runtime/tgbot.env

# 设置默认出口
echo "local" > runtime/current-exit

# 端口备注文件会自动创建
```
