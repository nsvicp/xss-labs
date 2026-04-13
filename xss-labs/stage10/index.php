<?php
/**
 * XSS Challenges - Stage #10
 * 14.6 绕过关键字domain
 * 
 * 漏洞成因：
 *   服务端过滤了 "domain" 关键字
 *   可以使用双写绕过（domain 被过滤后剩余 dom ain 组合）
 * 
 * 通关 Payload：
 *   <script>alert(document.domdomainain);</script>
 *   或 <script>alert(document['domain']);</script>
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #10</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #10</span>
  <h1>绕过关键字domain</h1>
  <span class="difficulty">难度：★★★★☆ 高级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">服务端过滤了 "domain" 关键字，可以使用双写绕过：domdomainain，或者使用数组方式：document['domain']</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <?php
    // 过滤 domain 关键字
    $filtered = str_replace('domain', '', $p1);
    ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo htmlspecialchars($filtered, ENT_QUOTES, 'UTF-8'); ?>" />
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
      <p>本关服务端过滤了 "domain" 关键字：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// 过滤 domain 关键字（区分大小写）</span>
<span class="hl-var">$filtered</span> = <span class="hl-php">str_replace</span>(<span class="hl-str">'domain'</span>, <span class="hl-str">''</span>, <span class="hl-var">$p1</span>);

<span class="hl-comment">// 直接拼接到 HTML 输出</span>
<span class="hl-php">echo</span> <span class="hl-str">"&lt;b&gt;"</span> . <span class="hl-var">$filtered</span> . <span class="hl-str">"&lt;/b&gt;"</span>;</div>
      <p>过滤策略分析：过滤了 <code>domain</code>（区分大小写）→ 直接使用 <code>document.domain</code> 会被移除关键字；未过滤 <code>&lt;</code> <code>&gt;</code> → 标签注入仍然可行。注意 <code>str_replace</code> 只做一次替换，而非递归替换。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：双写绕过原理</h3>
      <p>双写绕过利用了 <code>str_replace()</code> 的<strong>非递归</strong>特性。PHP 的 <code>str_replace()</code> 只从左到右扫描一次，不会对替换后的结果再次检查。</p>
      <p>因此，如果输入 <code>domdomainain</code>：</p>
      <div class="code-block"><span class="hl-comment">// 原始输入：    dom<span class="hl-inject">domain</span>ain</span>
<span class="hl-comment">// 匹配 domain：  ↑匹配到此处的 domain↑</span>
<span class="hl-comment">// 替换为空：    dom + ain</span>
<span class="hl-comment">// 最终结果：    domain ✅</span></div>
      <p>Payload 构造：</p>
      <div class="code-block">stage10.php?p1=<span class="hl-inject">&lt;script&gt;alert(document.domdomainain)&lt;/script&gt;</span></div>
      <p>服务端过滤后输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">&lt;script&gt;alert(document.domain)&lt;/script&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p><code>dom<span class="hl-inject">domain</span>ain</code> 中的 <code>domain</code> 被替换为空，剩余部分重新组合成 <code>domain</code>，脚本正常执行。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：使用方括号属性访问绕过</h3>
      <p>JavaScript 中，对象的属性可以通过字符串索引来访问。将 <code>document.domain</code> 改写为 <code>document['domain']</code>，由于 <code>domain</code> 字符串本身不会被 <code>str_replace</code> 中的 <code>domain</code> 匹配到……等等，实际上 <code>'domain'</code> 中仍包含 <code>domain</code> 字面量。</p>
      <p>但可以拆分字符串来绕过：</p>
      <div class="code-block"><span class="hl-comment">// 方法一：字符串拼接（不包含连续的 domain 字符串）</span>
<span class="hl-val">&lt;script&gt;alert(document['dom'+'ain'])&lt;/script&gt;</span></div>
      <p>服务端过滤 <code>domain</code> 后，<code>dom'+'ain</code> 中不包含完整的 <code>domain</code>，因此不会被匹配，过滤后原样输出。</p>
      <p>不过此 Payload 需要注意 <code>+</code> 号和引号在 URL 中需要正确编码，直接在地址栏输入时可用：</p>
      <div class="code-block">stage10.php?p1=<span class="hl-inject">&lt;script&gt;alert(document['dom'+'ain'])&lt;/script&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例3：str_replace 一次性替换的局限性</h3>
      <p>双写绕过的本质是利用了替换函数<strong>不做二次扫描</strong>的特性。对比不同替换方式的区别：</p>
      <div class="code-block"><span class="hl-comment">// str_replace — 只扫描一次（可被双写绕过）</span>
<span class="hl-var">$r</span> = <span class="hl-php">str_replace</span>(<span class="hl-str">'domain'</span>, <span class="hl-str">''</span>, <span class="hl-str">'domdomainain'</span>);  <span class="hl-comment">// → 'domain'</span>

<span class="hl-comment">// 循环替换 — 多次扫描直到无匹配（更安全）</span>
<span class="hl-php">while</span> (<span class="hl-php">strpos</span>(<span class="hl-var">$r</span>, <span class="hl-str">'domain'</span>) !== <span class="hl-php">false</span>) {
    <span class="hl-var">$r</span> = <span class="hl-php">str_replace</span>(<span class="hl-str">'domain'</span>, <span class="hl-str">''</span>, <span class="hl-var">$r</span>);
}
<span class="hl-comment">// 'domdomainain' → 'domain' → ''（双写也被清除）</span></div>
      <p>但即使使用循环替换，如果攻击者将字符串拆分为更小的碎片，仍然可能绕过。例如 <code>d</code> + <code>o</code> + <code>m</code> + <code>a</code> + <code>i</code> + <code>n</code>，无论如何都不会被 <code>str_replace('domain', ...)</code> 匹配。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果服务端使用 <code>str_ireplace('domain', '', $p1)</code>（不区分大小写），双写绕过还有效吗？</p>
      <p><strong>答：</strong>仍然有效。<code>str_ireplace()</code> 只是将匹配改为不区分大小写，但它仍然是<strong>非递归</strong>的一次性替换。<code>domdomainain</code> → <code>domain</code>，双写绕过的原理不依赖于大小写。</p>
      <p>真正防御关键字替换绕过的方案不是改进替换函数，而是从根本上改变策略——使用<strong>白名单验证</strong>（只允许安全字符通过），或使用 CSP（Content Security Policy）限制脚本执行。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
