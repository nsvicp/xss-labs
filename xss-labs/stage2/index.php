<?php
/**
 * XSS Challenges - Stage #2
 * 13.2.2 属性中的 XSS 注入
 * 
 * 漏洞成因：
 *   用户输入被插入到 <input> 标签的 value 属性中，未过滤
 *   <b> 标签输出使用 htmlspecialchars 严格过滤，无漏洞
 * 
 * 通关 Payload：
 *   "><script>alert(document.domain);</script>
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #2</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #2</span>
  <h1>属性中的 XSS 注入</h1>
  <span class="difficulty">难度：★★☆☆☆ 初级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">尝试闭合 input 标签的 value 属性：&quot;&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第二关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo $p1; ?>" placeholder="请输入搜索内容…" autocomplete="off" />
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?><b><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></b><?php else: ?><span class="result-empty">暂无搜索记录</span><?php endif; ?>
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
      <p>本关服务端的核心代码如下，注意两处输出的差异：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1，无任何过滤</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// ❌ 漏洞：直接拼接到 input 的 value 属性，无过滤</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo $p1; ?&gt;"</span><span class="hl-tag">&gt;</span>

<span class="hl-comment">// ✅ 安全：输出到 &lt;b&gt; 标签，使用 htmlspecialchars 严格过滤</span>
<span class="hl-tag">&lt;b&gt;</span>&lt;?php echo <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$p1</span>, ENT_QUOTES, <span class="hl-str">'UTF-8'</span>); ?&gt;<span class="hl-tag">&lt;/b&gt;</span></div>
      <p>同一个参数，在 <code>&lt;b&gt;</code> 标签中被安全过滤，而在 <code>&lt;input value&gt;</code> 属性中未作任何处理。这是本关的关键：<strong>漏洞不在文本节点，而在属性值</strong>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：为什么 &lt;b&gt; 标签里的注入无效？</h3>
      <p>向 <code>&lt;b&gt;</code> 输出前调用了 <code>htmlspecialchars()</code>，所有特殊字符被转义：</p>
      <div class="code-block"><span class="hl-comment">// 输入：&lt;script&gt;alert(1);&lt;/script&gt;</span>
<span class="hl-comment">// 输出：&amp;lt;script&amp;gt;alert(1);&amp;lt;/script&amp;gt;</span>
<span class="hl-tag">&lt;b&gt;</span>&amp;lt;script&amp;gt;alert(1);&amp;lt;/script&amp;gt;<span class="hl-tag">&lt;/b&gt;</span></div>
      <p>浏览器将其渲染为纯文本，脚本<strong>不会执行</strong>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：闭合 value 属性注入 Script 标签</h3>
      <p>用户输入被直接插入到 input 的 value 属性中（无过滤）：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject">【$p1 的值】</span>"</span><span class="hl-tag">&gt;</span></div>
      <p>输入位于双引号包裹的属性值内，需先闭合双引号、再闭合标签，才能注入脚本。Payload：</p>
      <div class="code-block">p1=<span class="hl-inject">&quot;&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>服务端实际输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">"<span class="hl-inject">&quot;&gt;</span>"</span><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>解析过程：</p>
      <ul>
        <li><code>"</code> — 闭合 value 属性的双引号</li>
        <li><code>&gt;</code> — 闭合 input 标签</li>
        <li><code>&lt;script&gt;alert(document.domain);&lt;/script&gt;</code> — 独立的脚本标签被浏览器执行</li>
      </ul>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果 input 标签的 value 属性用的是<strong>单引号</strong>包裹（<code>value='xxx'</code>），Payload 应该怎么调整？</p>
      <p><strong>答：</strong>需要用单引号闭合属性值。Payload 改为：</p>
      <div class="code-block">p1=<span class="hl-inject">&#39;&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>核心原则：先确认属性值的引号类型（单引号或双引号），用对应的引号闭合后再注入 HTML 标签。这就是为什么 <code>htmlspecialchars($p1, ENT_QUOTES)</code> 中的 <code>ENT_QUOTES</code> 参数很重要——它会同时转义单引号和双引号。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
