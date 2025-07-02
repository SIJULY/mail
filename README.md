一键安装脚本： bash <(curl -sSL https://raw.githubusercontent.com/SIJULY/mail/main/install.sh)



# 轻量级邮件收发与管理系统

这是一个非常典型的自托管 (Self-Hosted)、轻量级 (Lightweight) 的邮件解决方案，它巧妙地将专业的邮件收发服务与一个灵活的Web应用结合了起来。

## 项目模式 (技术架构)

这个项目采用了一种现代、高效的分离式服务架构，将复杂的邮件收发任务分解为几个独立且清晰的模块：

### 邮件接收层 (Receiving Layer) - `aiosmtpd`
我们没有使用像 Postfix 或 Exim 这样庞大而复杂的传统邮件传输代理 (MTA)，而是采用了一个基于 Python `asyncio` 的轻量级异步SMTP服务器 `aiosmtpd`。它的唯一职责就是监听端口25，像一个专注的门卫，接收所有投递来的邮件，然后立即将原始邮件内容转交给后端应用处理。这种模式极大地降低了资源消耗和配置的复杂性。

### Web应用与API层 (Application & API Layer) - `Flask` + `Gunicorn`
这是整个系统的“大脑”和“脸面”。我们使用轻量级的 Python Web 框架 Flask 来构建所有的网页界面（如登录页、收件箱、写邮件页面）和API接口。为了能在生产环境中稳定运行，我们使用 Gunicorn 作为应用服务器，它负责管理多个 Flask 应用进程，确保系统能高效地处理来自您浏览器的并发请求。这个Web服务运行在一个非标准的端口（如 2099）上，与邮件接收服务完全分离，互不干扰。

### 数据存储层 (Data Storage Layer) - `SQLite`
所有邮件内容、用户信息（加密后的密码）都存储在一个单一的 `emails.db` 文件中。选择 SQLite 的优点是零配置、自包含、无需额外安装数据库服务，非常适合这种轻量级的个人项目，备份和迁移也极其方便。

### 邮件发送层 (Sending Layer) - SMTP 中继模式 (SMTP Relay)
我们没有在服务器上搭建自己的发信服务，这是整个项目最明智的一个架构决策。我们采用的是业界推荐的 SMTP 中继模式。当您点击“发送邮件”时，我们的应用会作为一个客户端，通过加密端口（如 587）连接到专业的第三方邮件服务商（如 SendGrid）。所有复杂的发信任务，包括处理 PTR/SPF/DKIM 记录、维护IP信誉等，都外包给了这些专业服务。

#### 获取 SendGrid SMTP 凭证（API) 完整步骤

##### 第1步：注册 SendGrid 账户
访问官网：前往 SendGrid 官网。
开始免费使用：点击页面上的 "Start for Free" 或类似按钮。
填写信息：按照要求填写您的邮箱、密码，并创建账户。
激活账户：SendGrid 会向您的注册邮箱发送一封确认邮件，请务必登录您的邮箱，点击邮件中的链接来激活您的 SendGrid 账户。

##### 第2步：验证发信域名（最关键的一步）
这是最重要的一步。您必须向 SendGrid 证明您拥有 mail.sijuly.nyc.mn 这个域名（或者其主域名 sijuly.nyc.mn），这样 SendGrid 才允许您用这个域名下的地址作为发件人。这也可以极大地提高您邮件的送达率，避免被当成垃圾邮件。
登录 SendGrid：登录到您的 SendGrid 仪表盘。

进入发件人认证：在左侧菜单中找到 Settings -> Sender Authentication。

认证您的域名：在 “Domain Authentication” 部分，点击 Authenticate Your Domain 或 Get Started 按钮。

选择DNS服务商：它会问您的DNS托管服务商是谁（比如 GoDaddy, Cloudflare 等）。如果您不确定，可以直接选择 “Other Host (Not Listed)”。

输入您的域名：在输入框中，输入您要用于发信的主域名。对于 mail.sijuly.nyc.mn 来说，您应该输入根域名： sijuly.nyc.mn

获取DNS记录：点击“Next”后，SendGrid 会为您生成 3条 CNAME 类型的DNS记录。页面上会清楚地列出每一条记录的 “主机”(Host/Name) 和 “值”(Value/Points To)。

它们看起来会是这样（这只是例子，请以您页面上显示的为准）：
Host: em123.sijuly.nyc.mn, Value: u456789.wl.sendgrid.net
Host: s1._domainkey.sijuly.nyc.mn, Value: s1.domainkey.u456789.wl.sendgrid.net
Host: s2._domainkey.sijuly.nyc.mn, Value: s2.domainkey.u456789.wl.sendgrid.net

添加DNS记录：
现在，请打开一个新的浏览器标签页，登录到您购买 sijuly.nyc.mn 域名的服务商的DNS管理后台。
完全按照 SendGrid 页面上提供的信息，创建这3条 CNAME 记录。将 SendGrid 提供的“Host”和“Value”分别复制粘贴到您DNS后台的对应输入框中。

在 SendGrid 上进行验证：
添加完DNS记录后，回到 SendGrid 的页面，勾选 “I've added these records.”，然后点击 Verify 按钮。
DNS记录的生效需要一些时间，从几分钟到几个小时不等。如果第一次验证失败，请不要着急，可以过一段时间再回来点击 Verify 按钮。

一旦成功，您会看到一个绿色的 “Verified” 状态。
##### 第3步：创建并保存 API 密钥
这个 API 密钥就是我们用来登录 SMTP 服务的“密码”，它的权限很高，必须妥善保管。

进入API密钥页面：在 SendGrid 左侧菜单中，找到 Settings -> API Keys。

创建API密钥：点击页面右上角的 “Create API Key” 按钮。

填写信息：
给您的密钥起一个名字，比如 my-vps-mailer，方便您识别。
选择 “Full Access”（完全权限）。
点击 “Create & View”。

复制并保存密钥：
这是唯一一次您能看到完整的密钥！ SendGrid 会显示一串以 SG. 开头的非常长的字符。
请立刻点击复制按钮，并将它粘贴到您本地一个绝对安全的地方（比如您的密码管理器或一个加密的记事本中）。
一旦您离开这个页面，就再也无法看到完整的密钥了。


## 项目优点 (Advantages)

基于以上的技术架构，这个项目拥有以下显著的优点：

* **轻量与高效 (Lightweight & Efficient)**
  相比于需要持续占用大量系统资源的传统邮件服务器，我们的方案资源消耗极低，非常适合在小规格的VPS（如甲骨文云的免费实例）上流畅运行。

* **完全的控制权与隐私 (Full Control & Privacy)**
  所有接收到的邮件数据都存储在您自己的服务器上，您拥有100%的数据所有权和控制权，无需担心第三方服务扫描您的邮件内容。

* **高送达率与低维护成本 (High Deliverability & Low Maintenance)**
  通过使用专业的SMTP中继服务发信，我们巧妙地绕过了云服务商对25端口的封锁，并借助服务商的高信誉IP地址，确保了您发送的邮件能被Gmail、Outlook等主流邮箱正常接收，而不会被当作垃圾邮件。这为您省去了维护IP信誉这一最头疼、最昂贵的工作。

* **高度可定制与可扩展 (Highly Customizable & Extensible)**
  整个系统完全由 Python 构建，代码逻辑清晰。未来您可以非常方便地增加新功能，比如：根据特定规则自动回复邮件、将邮件内容推送到其他应用、增加更复杂的邮件过滤规则等。

* **安全可靠 (Secure & Reliable)**
  采用了多用户系统，每个用户的密码都经过哈希加密存储，保证了密码安全。通过数据隔离确保了普通用户只能看到自己的邮件。通过独立的管理员角色和密码验证，实现了安全的全局管理。使用 `systemd` 进行服务管理，保证了程序的稳定运行和开机自启。
