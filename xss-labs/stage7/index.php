<?php
/**
 * XSS Challenges - Stage #7
 * 14.3 限制输入引号和尖括号的XSS注入
 *
 * 漏洞成因：
 *   服务端过滤了单引号、双引号、尖括号
 *   input 标签属性未使用引号包裹 value 值
 *   空格即可让 p1 的值逃逸出 value 属性，注入事件属性
 *
 * 通关 Payload：
 *   123 onmouseover=alert(document.domain)
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// 过滤单引号、双引号，尖括号替换为空
$filtered = str_replace(['<', '>'], '', str_replace(['"', "'"], '', $p1));
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #7</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #7</span>
  <h1>限制输入引号的XSS注入</h1>
  <span class="difficulty">难度：★★★☆☆ 中级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">注意观察页面源码，input 标签的 value 属性没有使用引号包裹。过滤了引号，但可以用空格逃逸 value 属性，注入事件属性。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第七关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type=text name=p1 <?php if ($searched): ?>value=<?php echo $filtered; ?><?php endif; ?> />
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
      <p>本关服务端对输入进行了"双重标准"的处理：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// 过滤单引号、双引号，&lt;&gt; 替换为空</span>
<span class="hl-var">$filtered</span> = <span class="hl-php">str_replace</span>([<span class="hl-str">'&lt;'</span>, <span class="hl-str">'&gt;'</span>], <span class="hl-str">''</span>, <span class="hl-php">str_replace</span>([<span class="hl-str">'"'</span>, <span class="hl-str">'\''</span>], <span class="hl-str">''</span>, <span class="hl-var">$p1</span>));

<span class="hl-comment">// ⚠️ input 标签的 type、name、value 属性都没有使用引号包裹，且过滤不全</span>
<span class="hl-php">?&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">text</span> <span class="hl-attr">name</span>=<span class="hl-val">p1</span> <span class="hl-attr">value</span>=<span class="hl-inject">&lt;?php echo $filtered; ?&gt;</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">// ✅ b 标签回显：使用 htmlspecialchars 安全输出</span>
<span class="hl-tag">&lt;b&gt;</span>&lt;?php echo <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$p1</span>, <span class="hl-str">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>); ?&gt;<span class="hl-tag">&lt;/b&gt;</span></div>
      <p>搜索结果的 <code>&lt;b&gt;</code> 标签使用了 <code>htmlspecialchars()</code>，无法注入。<strong>突破点在 input 的 value 属性</strong>——没有引号包裹，虽然过滤了 <code>"</code> <code>'</code> <code>&lt;</code> <code>&gt;</code>，但空格未过滤，空格即可逃逸。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：无引号属性值中的空格逃逸</h3>
      <p>关键在于 input 标签的写法。对比两种写法的区别：</p>
      <div class="code-block"><span class="hl-comment">&lt;!-- 安全写法：value 用引号包裹 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">"用户输入"</span><span class="hl-tag">&gt;</span>
<span class="hl-comment">&lt;!-- 漏洞写法：value 没有引号包裹 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-inject">用户输入</span><span class="hl-tag">&gt;</span></div>
      <p>在 HTML 规范中，无引号的属性值遇到<strong>空格、大于号、换行符</strong>时自动结束。因此：</p>
      <div class="code-block"><span class="hl-comment">// 输入：123 onmouseover=alert(document.domain)</span>
<span class="hl-comment">// 服务端输出（引号被过滤，但不影响）：</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-inject">123</span> <span class="hl-inject">onmouseover</span>=<span class="hl-val">alert(document.domain)</span> <span class="hl-tag">/&gt;</span></div>
      <p>浏览器解析过程：value 的值为 <code>123</code>（到第一个空格结束）→ 后续的 <code>onmouseover=alert(document.domain)</code> 被解析为新的独立属性。当用户鼠标悬停在输入框上时，触发 alert。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：为什么引号过滤无效</h3>
      <p>本关过滤了双引号和单引号，目的是防止闭合带引号的属性值。但在无引号属性值上下文中，攻击者<strong>根本不需要引号</strong>来逃逸：</p>
      <div class="code-block"><span class="hl-comment">// 带引号属性值：需要引号闭合</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">"用户输入"</span><span class="hl-tag">&gt;</span>
<span class="hl-comment">// 攻击：" onmouseover=alert(1) "</span>
<span class="hl-comment">//       ↑ 需要双引号闭合 ↑</span>

<span class="hl-comment">// 无引号属性值：空格即可逃逸</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-inject">用户输入</span><span class="hl-tag">&gt;</span>
<span class="hl-comment">// 攻击：123 onmouseover=alert(1)</span>
<span class="hl-comment">//        ↑ 空格即逃逸 ↑</span></div>
      <p>Payload 构造：</p>
      <div class="code-block">stage7.php?p1=<span class="hl-inject">123 onmouseover=alert(document.domain)</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例3：其他事件属性 Payload</h3>
      <p>除了 onmouseover，还可以使用其他事件属性：</p>
      <div class="code-block"><span class="hl-comment">// 鼠标悬停触发</span>
<span class="hl-val">123 onmouseover=alert(document.domain)</span>

<span class="hl-comment">// 获得焦点时触发（配合 autofocus 自动触发）</span>
<span class="hl-val">123 onfocus=alert(document.domain) autofocus</span>

<span class="hl-comment">// 鼠标点击触发</span>
<span class="hl-val">123 onclick=alert(document.domain)</span></div>
      <p>注意：<code>onfocus=alert(1) autofocus</code> 可以实现<strong>无需用户交互</strong>的自动触发——页面加载后 input 自动获得焦点，触发 onfocus 事件。</p>
    </div>

    <div class="knowledge-item">
      <h3>例4：过滤策略对比分析</h3>
      <p>将前几关的过滤策略做一个对比：</p>
      <div class="code-block"><span class="hl-comment">// 第一关：无过滤                → 标签注入 ✅  属性注入 ✅</span>
<span class="hl-comment">// 第二关：b 标签过滤，属性无过滤 → 标签注入 ❌  属性注入 ✅</span>
<span class="hl-comment">// 第六关：过滤 &lt; &gt;             → 标签注入 ❌  属性注入 ✅</span>
<span class="hl-comment">// 第七关：b 标签安全，input 过滤 " ' &lt; &gt;，但无引号 → b 标签安全  input ✅</span></div>
      <p>第七关过滤了引号和尖括号，看似防护更强，但因为 value <strong>没有使用引号包裹</strong>，过滤引号毫无意义——攻击者只需要空格就能逃逸。<code>&lt;b&gt;</code> 标签使用了 <code>htmlspecialchars()</code> 安全输出，没有漏洞。这说明<strong>过滤必须结合输出上下文来设计</strong>，脱离上下文的过滤永远不完整。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>为什么 HTML 属性值不使用引号也能被浏览器正确解析？这是规范允许的吗？</p>
      <p><strong>答：</strong>是的，HTML 规范确实允许属性值不使用引号。根据 HTML5 规范，无引号属性值可以包含除<strong>空格、制表符、换行符、换页符、<code>=</code>、<code>&lt;</code>、<code>&gt;</code>、<code>&quot;</code>、<code>&apos;</code>、<code>`</code></strong>以外的任何字符。当遇到这些分隔符时，属性值自动结束。</p>
      <p>正因为无引号属性值以空格为分隔符，所以攻击者只需一个空格就能让输入值逃逸出属性值的范围。这也是为什么所有 HTML 属性值<strong>都应该使用引号包裹</strong>——这不仅是一种编码规范，更是一项安全措施。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
