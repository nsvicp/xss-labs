<?php
/**
 * XSS Challenges - Stage #1
 * 13.2.1 无过滤的 XSS 注入
 *
 * 漏洞成因：
 *   $_GET['p1'] 用户输入未经任何过滤或编码，
 *   直接拼接到 HTML 的 <b> 标签中输出。
 *   攻击者可通过构造 Payload 注入任意 JavaScript。
 *
 * 通关 Payload 示例：
 *   <script>alert(document.domain);</script>
 *   1</b><script>alert(document.domain);</script>
 */

// 获取用户提交的参数 p1（无任何过滤）
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #1</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #1</span>
  <h1>无过滤的 XSS 注入</h1>
  <span class="difficulty">难度：★☆☆☆☆ 入门</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">直接在搜索框中输入 &lt;script&gt;alert(document.domain);&lt;/script&gt; 即可通关。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第一关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" placeholder="请输入搜索内容…" autocomplete="off" />
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?><b><?php echo $p1; ?></b><?php else: ?><span class="result-empty">暂无搜索记录</span><?php endif; ?>
      </div>
    </div>
  </div>

  <div class="knowledge-section">
    <button class="knowledge-toggle" onclick="this.parentElement.classList.toggle('expanded')">
      <span class="toggle-icon">▶</span> 知识点解析
    </button>
    <div class="knowledge-content">

    <div class="knowledge-item">
      <h3>后端 PHP 漏洞代码</h3>
      <p>本关服务端的核心漏洞代码如下：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1，无任何过滤</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// 直接拼接到 HTML 输出，未调用 htmlspecialchars()</span>
<span class="hl-php">echo</span> <span class="hl-str">"&lt;b&gt;"</span> . <span class="hl-var">$p1</span> . <span class="hl-str">"&lt;/b&gt;"</span>;</div>
      <p>安全写法应使用 <code>htmlspecialchars()</code> 对输出进行 HTML 实体编码：</p>
      <div class="code-block"><span class="hl-comment">// ✅ 安全写法</span>
<span class="hl-php">echo</span> <span class="hl-str">"&lt;b&gt;"</span> . <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$p1</span>, <span class="hl-str">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>) . <span class="hl-str">"&lt;/b&gt;"</span>;</div>
    </div>

    <div class="knowledge-item">
      <h3>例1：直接注入 Script 标签</h3>
      <p>用户输入被插入到如下结构中：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">【$p1 的值】</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p>在搜索框输入以下 Payload，URL 变为：</p>
      <div class="code-block">stage1.php?p1=<span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>服务端输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p>浏览器解析 HTML 时，将 <code>&lt;script&gt;</code> 识别为合法标签并执行其中的 JavaScript 代码，弹出 <code>alert</code> 对话框。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：使用闭合标签方式进行反射型 XSS 注入</h3>
      <p>在搜索框输入以下 Payload：</p>
      <div class="code-block"><span class="hl-inject">1&lt;/b&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>服务端输出的 HTML 源码变为：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">1&lt;/b&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p><code>&lt;b&gt;</code> 标签成功闭合，脚本被执行，末尾多余的 <code>&lt;/b&gt;</code> 被浏览器自动忽略。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong><code>&lt;b&gt;</code> 标签的文本内容是用双引号引起来的（<code>echo "&lt;b&gt;"</code>），为什么不需要先用双引号闭合？</p>
      <p><strong>答：</strong>这里的双引号只是 PHP 字符串的定界符，并非 HTML 属性值的引号。PHP 执行 <code>echo</code> 后输出的是纯 HTML 内容，浏览器接收到的是：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span>用户输入<span class="hl-tag">&lt;/b&gt;</span></div>
      <p>此时用户输入位于 HTML 标签的<strong>文本内容</strong>中，而非<strong>属性值</strong>中。因此只需要闭合 HTML 标签（<code>&lt;/b&gt;</code>），而不需要处理引号。多余的 <code>&lt;/b&gt;</code> 会被浏览器自动纠错忽略，不影响脚本执行。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
