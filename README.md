# 浙江传媒学院 OA 内网-爬虫项目
- - -
>### 项目介绍 Introduce
对内网发布信息进行采集，通过用户名和密码换取 Cookie 信息，登录内网，访问内网页面，进行数据抓取和整理，用于客制化信息整理展示等服务。

项目使用 Node.js 开发，可快速部署至后端平台。

在后续开发中，将使用腾讯云提供 CloudBase 云开发 平台进行后端开发。

>### 开发日志 Daily
2022-04-04：

实现内网登录，换取 Cookie


>### 项目结构 Structure
**oa-login.js**

使用用户名和密码进行登录，换取 Cookie

**security.js**

基于 RSA 的公私钥加解密模块，修改成后端可用的版本，仅暴露加密接口。

