<?php
/**
 * XSS Challenges - Stage #6
 * 14.2 限制输入<>的XSS注入
 * 
 * 漏洞成因：
 *   服务端对 <（删除）和 >（转义）进行了处理
 *   但没有过滤双引号，可通过事件属性绕过
 * 
 * 通关 Payload：
 *   " onmouseover="alert(document.domain)
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #6</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #6</span>
  <h1>限制输入<>的XSS注入</h1>
  <span class="difficulty">难度：★★★☆☆ 中级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">服务端对 &lt; 删除、对 &gt; 转义，但双引号未被过滤，可以使用事件属性绕过：" onmouseover="alert(document.domain)</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第六关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <?php
    // 过滤 <（删除），> 转义为 &gt;
    $filtered = str_replace('>', '&gt;', str_replace('<', '', $p1));
    ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo $filtered; ?>" placeholder="请输入搜索内容…" autocomplete="off" />
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?><b><?php echo $filtered; ?></b><?php else: ?><span class="result-empty">暂无搜索记录</span><?php endif; ?>
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
      <p>本关服务端对 <code>&lt;</code> 和 <code>&gt;</code> 进行了处理，但方式不同：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// &lt; 删除，&gt; 转义为 &amp;gt;</span>
<span class="hl-var">$filtered</span> = <span class="hl-php">str_replace</span>(<span class="hl-str">'&gt;'</span>, <span class="hl-str">'&amp;gt;'</span>, <span class="hl-php">str_replace</span>(<span class="hl-str">'&lt;'</span>, <span class="hl-str">''</span>, <span class="hl-var">$p1</span>));

<span class="hl-comment">// 直接拼接到 HTML 输出</span>
<span class="hl-php">echo</span> <span class="hl-str">"&lt;b&gt;"</span> . <span class="hl-var">$filtered</span> . <span class="hl-str">"&lt;/b&gt;"</span>;</div>
      <p>输入框和搜索结果的 <code>&lt;b&gt;</code> 标签都使用了这个过滤后的值。<code>&lt;</code> 被删除后无法开标签，<code>&gt;</code> 被转义后标签语法不完整，因此传统的 <code>&lt;script&gt;</code> 注入失效。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：注入上下文分析</h3>
      <p>过滤后，用户输入被插入到如下结构中：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">【过滤后的 $p1：&lt;被删除，&gt;被转义】</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p>由于 <code>&lt;</code> 被删除，无法开标签；<code>&gt;</code> 被转义为实体，即使有残留也无法正确闭合标签。传统标签注入方式失效。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：利用事件属性绕过 —— 为什么可以？</h3>
      <p>虽然 <code>&lt;</code> 被删除、<code>&gt;</code> 被转义，但双引号未被过滤。攻击点在于 input 的 value 属性——Payload 不需要 <code>&lt;</code> 就能注入事件属性。</p>
      <p>Payload 构造（通过 URL 直接提交）：</p>
      <div class="code-block">stage6.php?p1=<span class="hl-inject">" onmouseover="alert(document.domain)</span></div>
      <p>服务端过滤后（<code>&gt;</code> 被转义），输出到输入框中（浏览器再次编码后）：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">name</span>=<span class="hl-val">"p1"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject">" onmouseover="alert(document.domain)</span>"</span> <span class="hl-tag">/&gt;</span></div>
      <p>浏览器解析时，第一个 <code>"</code> 闭合了 value 属性值，后面的 <code>onmouseover="alert(document.domain)"</code> 被解析为新的独立属性。当用户鼠标悬停在输入框上时，触发 <code>alert</code>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：理解过滤的局限性</h3>
      <p>服务端仅过滤了两个字符，但 XSS 的触发方式远不止 <code>&lt;script&gt;</code> 标签注入一种。常见的事件属性注入方式包括：</p>
      <div class="code-block"><span class="hl-comment">// onmouseover —— 鼠标悬停时触发</span>
<span class="hl-val">" onmouseover="alert(document.domain)</span>

<span class="hl-comment">// onfocus —— 获得焦点时触发（配合 autofocus）</span>
<span class="hl-val">" onfocus="alert(document.domain)" autofocus="</span>

<span class="hl-comment">// onclick —— 点击时触发</span>
<span class="hl-val">" onclick="alert(document.domain)</span></div>
      <p>这些 Payload 都不需要 <code>&lt;</code> 和 <code>&gt;</code>，只需双引号来闭合属性值。因此，<strong>黑名单过滤永远不完整</strong>——只要遗漏了任何可利用的字符或属性，就存在被绕过的风险。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果同时过滤了 <code>&lt; &gt; &quot; '</code> 三种字符，还能进行 XSS 攻击吗？</p>
      <p><strong>答：</strong>过滤了尖括号和引号后，直接的事件属性注入也被阻止了。但如果输出上下文是在 JavaScript 代码中（如 <code>var name = "用户输入";</code>），还可以通过 <code>\</code> 反斜杠逃逸或 <code>-</code>、<code>+ </code> 等运算符构造新的注入语句。安全的做法是使用 <code>htmlspecialchars($input, ENT_QUOTES, 'UTF-8')</code> 统一编码，而非手动过滤个别字符。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
