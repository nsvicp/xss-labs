<?php
/**
 * XSS Challenges - Stage #4
 * 13.2.4 在隐藏域中注入 XSS
 *
 * 漏洞成因：
 *   p2 参数被直接拼接到 <input type="hidden"> 的 value 属性中
 *   需要闭合属性值和标签后注入脚本
 *
 * 通关 Payload：
 *   p2="><script>alert(document.domain);</script>
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$p2 = isset($_GET['p2']) ? $_GET['p2'] : 'hackme';
$searched = isset($_GET['p1']) || isset($_GET['p2']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #4</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #4</span>
  <h1>在隐藏域中注入 XSS</h1>
  <span class="difficulty">难度：★★☆☆☆ 初级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在页面中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>搜索框参数 <code style="color:#e94560;">p1</code> 已做安全过滤，尝试从隐藏参数 <code style="color:#e94560;">p2</code> 入手，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">invisible input field - 页面中有一个隐藏的 input 标签，p2 参数被直接拼接到它的 value 属性中。查看源代码（F12）找到它。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第四关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span>&amp;<span class="url-key">p2</span>=<span class="url-val"><?php echo htmlspecialchars($p2, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" placeholder="请输入搜索内容…" autocomplete="off" />
      <input type="hidden" name="p2" value="<?php echo $p2; ?>">
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?>
          <p><strong>p1 搜索内容：</strong><b><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></b></p>
        <?php else: ?>
          <span class="result-empty">暂无搜索记录</span>
        <?php endif; ?>
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
      <p>本关有两个参数，安全处理方式完全不同：</p>
      <div class="code-block"><span class="hl-comment">// 获取参数，p2 默认值为 hackme</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;
<span class="hl-var">$p2</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p2'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p2'</span>] : <span class="hl-str">'hackme'</span>;

<span class="hl-comment">// ✅ p1 搜索框：使用 htmlspecialchars 安全输出</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo htmlspecialchars($p1); ?&gt;"</span><span class="hl-tag">&gt;</span>

<span class="hl-comment">// ❌ p2 隐藏域：直接拼接，无过滤（唯一漏洞点）</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"hidden"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo $p2; ?&gt;"</span><span class="hl-tag">&gt;</span></div>
      <p>开发者以为隐藏域在页面上不可见，用户无法与之交互，就忽略了过滤。但实际上 <code>type="hidden"</code> 只是不显示控件，其 value 属性中的内容仍然会被浏览器解析。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：闭合隐藏域注入 Script 标签</h3>
      <p>隐藏域本质上就是一个普通 input 标签，漏洞原理与第二关完全一致——用户输入在属性值中，需要先闭合双引号和标签：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"hidden"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject">【$p2 的值】</span>"</span><span class="hl-tag">&gt;</span></div>
      <p>Payload 构造：</p>
      <div class="code-block">stage4.php?p1=test&amp;p2=<span class="hl-inject">&quot;&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>服务端输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"hidden"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject">&quot;&gt;</span>"</span><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>解析过程：闭合双引号 <code>"</code> → 闭合标签 <code>&gt;</code> → 注入脚本 <code>&lt;script&gt;</code>。虽然隐藏域不可见，但注入的 <code>&lt;script&gt;</code> 标签已经脱离了属性值的上下文，进入 HTML 文档流，浏览器照样会执行。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：为什么 p1 搜索框不能注入？</h3>
      <p>搜索框使用了 <code>htmlspecialchars</code> 进行输出编码。输入 <code>"&gt;&lt;script&gt;</code> 后：</p>
      <div class="code-block"><span class="hl-comment">// 原始输入："&gt;&lt;script&gt;alert(1);&lt;/script&gt;</span>
<span class="hl-comment">// 编码后：  &amp;quot;&amp;gt;&amp;lt;script&amp;gt;alert(1);&amp;lt;/script&amp;gt;</span>

<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">"&amp;quot;&amp;gt;&amp;lt;script&amp;gt;alert(1);&amp;lt;/script&amp;gt;"</span><span class="hl-tag">&gt;</span></div>
      <p>浏览器将 <code>&amp;quot;</code> 等实体渲染为普通文本字符，<code>&lt;script&gt;</code> 不会被视为 HTML 标签，脚本无法执行。</p>
    </div>

    <div class="knowledge-item">
      <h3>新思路：不闭合标签，利用隐藏域自带事件触发 XSS</h3>
      <p>上述两种方法都需要闭合 value 属性的双引号。但在 2024 年 9 月之后，主流浏览器新增了对 <code>oncontentvisibilityautostatechange</code> 事件的支持，提供了一种<strong>无需闭合引号</strong>的新型隐藏域 XSS 攻击方式：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">hidden</span> <span class="hl-inject">oncontentvisibilityautostatechange</span>=<span class="hl-val">alert(document.domain)</span> <span class="hl-inject">style</span>=<span class="hl-val">content-visibility:auto</span><span class="hl-tag">&gt;</span></div>
      <p>原理分析：</p>
      <ul>
        <li><code>oncontentvisibilityautostatechange</code> — 当 CSS <code>content-visibility</code> 属性值在 <code>auto</code> 和 <code>hidden</code> 之间切换时触发的事件</li>
        <li><code>style=content-visibility:auto</code> — 设置 CSS 属性，使元素进入"内容可见性自动"状态</li>
        <li><code>type=hidden</code> — 隐藏域本身会触发可见性状态变化，从而自动触发事件处理器中的 JavaScript 代码</li>
      </ul>
      <p>因此，如果用户输入被拼接到隐藏域的属性列表中（而非 value 的值中），攻击者可以不闭合任何引号，直接注入新属性：</p>
      <div class="code-block">stage4.php?p2=<span class="hl-inject"> oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto</span></div>
      <p>服务端输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"hidden"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject"> oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto</span>"</span><span class="hl-tag">&gt;</span></div>
      <p>浏览器解析时，HTML 属性的引号优先匹配最前面的 <code>"</code>，因此 value 的值在第一个空格处就结束了，后续的 <code>oncontentvisibilityautostatechange</code> 和 <code>style</code> 被解析为独立属性。这种攻击方式<strong>完全不需要闭合引号</strong>，是对传统隐藏域 XSS 的重要补充。</p>
      <p><strong>浏览器支持：</strong>该功能于 2024 年 9 月首次被 Chrome、Edge、Firefox 等主流浏览器广泛支持。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>隐藏域（<code>type="hidden"</code>）的 value 中注入的脚本，用户看不到任何可见的输入框，脚本还能执行吗？</p>
      <p><strong>答：</strong>能。<code>type="hidden"</code> 只是让 input 不渲染为可见控件，但它仍然是 HTML 文档的一部分。浏览器解析 HTML 时，会一视同仁地处理所有标签。只要注入的代码被释放到文档流中（不在属性值引号内），<code>&lt;script&gt;</code> 标签就会被正常执行。</p>
      <p>这就是为什么"<strong>看不见的地方不代表安全</strong>"——隐藏域、HTML 注释、meta 标签、URL 参数等不可见位置，同样需要做好输出编码。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
