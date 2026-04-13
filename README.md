# XSS Challenges 靶场

XSS 学习靶场。

## 关卡列表

| 关卡 | 名称 | 核心知识点 |
|------|------|-----------|
| Stage 1 | 无过滤的 XSS 注入 | 基础 payload 测试，无任何过滤 |
| Stage 2 | 属性中的 XSS 注入 | HTML 属性 value 中的 XSS 注入点 |
| Stage 3 | 选择列表中的 XSS 注入 | p2 参数直接输出到 b 标签 |
| Stage 4 | 隐藏域中注入 XSS | input hidden value 属性注入 |
| Stage 5 | 限制输入长度 | 使用工具截包修改参数绕过长度限制 |
| Stage 6 | 限制输入尖括号 | 过滤 < > 但未过滤双引号，事件属性绕过 |
| Stage 7 | 限制输入引号和尖括号 | input value 无引号包裹，空格逃逸 |
| Stage 8 | JavaScript 伪协议 | href 属性注入 javascript: 伪协议 |
| Stage 10 | 绕过关键字 domain | 双写绕过 / 数组绕过 |
| Stage 11 | 绕过多条正则过滤规则 | 正则过滤，空白字符 / 控制字符绕过 |
| Stage 12 | IE 反引号属性值绕过 | IE 浏览器反引号绕过 |
| Stage 13 | CSS javascript 伪协议注入 | style 属性注入（仅 IE） |
| Stage 14 | CSS expression 绕过正则过滤 | CSS 注释分割关键字（仅 IE） |
| Stage 15 | 十六进制绕过 | JS \x 转义序列 |
| Stage 16 | Unicode 绕过 | JS \u 转义序列 |

## 免责声明

本靶场仅供安全学习使用，请勿用于非法途径。
