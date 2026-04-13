# XSS Challenges 靶场

XSS 学习靶场。

## 关卡列表

| 关卡 | 名称 | 核心知识点 |
|------|------|-----------|
| Stage 1 | 初识反射型 XSS | 基础 payload 测试，无任何过滤 |
| Stage 2 | 属性值注入 | HTML 属性中的 XSS 注入点 |
| Stage 3 | 事件属性注入 | onclick、onerror 等事件触发 |
| Stage 4 | 伪协议注入 | javascript:、data: 等协议 |
| Stage 5 | 链接注入 | a href 标签属性注入 |
| Stage 6 | 大小写绕过 | strtolower/不区分大小写过滤 |
| Stage 7 | 双写绕过 | str_replace 单次替换漏洞 |
| Stage 8 | UTF-7 编码 | 字符集编码绕过 |
| Stage 10 | HTML 实体编码 | &lt; &gt; 等实体的绕过 |
| Stage 11 | 路径穿越 | URL 参数与反射型 XSS |
| Stage 12 | Cookie XSS | 从 URL 注入到页面显示 |
| Stage 13 | CSS 注入 | style 属性中的 XSS |
| Stage 14 | CSS 表达式 | expression() 动态样式 |
| Stage 15 | 十六进制绕过 | JS \x 转义序列 |
| Stage 16 | Unicode 绕过 | JS \u 转义序列 |


## 免责声明

本靶场仅供安全学习使用，请勿用于非法途径。
