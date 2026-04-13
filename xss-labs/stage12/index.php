<?php
/**
 * XSS Challenges - Stage #12
 * 15.1 IE浏览器反引号属性值绕过
 * 
 * 漏洞成因：
 *   input 标签的 value 属性没有使用引号包裹
 *   p1 参数被过滤了双引号和尖括号，无法用 " 闭合 value，也无法注入标签
 *   IE 浏览器支持反引号作为属性值引号
 *   可以用反引号闭合 value，插入事件属性执行 JS
 * 
 * 通关 Payload（仅 IE 可解）：
 *   123`onmouseover=alert(document.domain)
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);

// 过滤双引号和尖括号
$filtered = str_replace(['"', '<', '>'], '', $p1);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #12</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #12</span>
    <h1>IE浏览器反引号属性值绕过</h1>
    <span class="difficulty">难度：★★★★★ 专家</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">input 标签的 value 没有引号，但双引号被过滤了。IE 浏览器支持用反引号 \` 作为属性值引号，试试用它来闭合 value。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十二关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value=<?php echo $filtered; ?> >
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
      <p>本关有两个关键缺陷：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// ❌ 只过滤了双引号和尖括号</span>
<span class="hl-var">$filtered</span> = <span class="hl-php">str_replace</span>([<span class="hl-str">'"'</span>, <span class="hl-str">'&lt;'</span>, <span class="hl-str">'&gt;'</span>], <span class="hl-str">''</span>, <span class="hl-var">$p1</span>);

<span class="hl-comment">// ❌ value 属性没有使用任何引号包裹</span>
<span class="hl-php">echo</span> <span class="hl-str">'&lt;input type="text" value='</span> . <span class="hl-var">$filtered</span> . <span class="hl-str">' /&gt;'</span>;</div>
      <p><strong>缺陷分析：</strong></p>
      <ul>
        <li><code>value</code> 属性没有引号包裹，用户输入可以逃逸出属性值</li>
        <li>过滤了双引号 <code>"</code>，无法用 <code>" onmouseover=...</code> 来闭合</li>
        <li>过滤了尖括号 <code>&lt;</code> <code>&gt;</code>，无法注入新的 HTML 标签</li>
        <li>但<strong>反引号 <code>`</code> 和单引号 <code>'</code> 都没有被过滤</strong></li>
      </ul>
    </div>

    <div class="knowledge-item">
      <h3>例1：HTML5 中无引号属性值的终止规则</h3>
      <p>根据 HTML5 规范，无引号的属性值遇到以下字符就会终止：</p>
      <div class="code-block"><span class="hl-comment">/* 无引号属性值的终止字符 */</span>
空格（U+0020）    制表符（U+0009）    换行（U+000A）
回车（U+000D）    &lt;  &gt;  =  引号（" ' `）</div>
      <p>在现代浏览器中，反引号 <code>`</code> 也是终止字符之一。但在<strong>旧版 IE 浏览器</strong>中，反引号<strong>不会被当作终止字符</strong>，反而可以被 IE 解析为<strong>属性值的引号</strong>！</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：IE 浏览器的反引号特性</h3>
      <p>IE 浏览器（IE6/7）有一种独特的属性值解析行为——<strong>反引号可以作为属性值的定界符</strong>：</p>
      <div class="code-block"><span class="hl-comment">&lt;!-- 正常写法：双引号包裹属性值 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">"hello"</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">&lt;!-- IE 特有：反引号也可以包裹属性值 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">`hello`</span> <span class="hl-tag">/&gt;</span>   <span class="hl-comment">← IE6/7 中有效</span></div>
      <p>这意味着在 IE 中，反引号具有和双引号/单引号类似的"包裹属性值"的功能。攻击者可以利用这个特性来闭合原本未引号包裹的 value 属性。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：Payload 构造与注入过程</h3>
      <p>Payload 构造：</p>
      <div class="code-block">stage12.php?p1=<span class="hl-inject">123`onmouseover=alert(document.domain)</span></div>
      <p>服务端处理：</p>
      <div class="code-block"><span class="hl-comment">// 原始输入</span>
<span class="hl-var">$p1</span> = <span class="hl-str">"123`onmouseover=alert(document.domain)"</span>;

<span class="hl-comment">// str_replace 过滤双引号和尖括号 — 无变化（不含这些字符）</span>
<span class="hl-var">$filtered</span> = <span class="hl-str">"123`onmouseover=alert(document.domain)"</span>;</div>
      <p>服务端输出（IE6/7 视角）：</p>
      <div class="code-block"><span class="hl-comment">&lt;!-- IE 解析：反引号闭合 value，后面的内容被解析为新属性 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">value</span>=<span class="hl-val">`123`</span> <span class="hl-attr">onmouseover</span>=<span class="hl-val">alert(document.domain)</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">&lt;!-- 现代浏览器解析：反引号是终止字符，value=123 后直接解析新属性 --&gt;</span>
<span class="hl-comment">&lt;!-- 但这里 IE 和现代浏览器的理解一致，都是 value="123" --&gt;</span>
<span class="hl-comment">&lt;!-- 关键区别在于：IE 允许反引号作为引号来包裹值 --&gt;</span></div>
      <p>⚠️ <strong>注意：</strong>在 IE 中输入后需要<strong>鼠标悬停到 input 上</strong>才能触发 <code>onmouseover</code> 事件。也可以使用 <code>autofocus onfocus=alert(document.domain)</code> 来自动触发。</p>
    </div>

    <div class="knowledge-item">
      <h3>例4：各路注入方式为何全部失效？</h3>
      <p>来看看常见的注入方式在本关为什么行不通：</p>
      <div class="code-block"><span class="hl-comment">// 方式1：双引号闭合 — ❌ 被过滤</span>
p1=<span class="hl-inject">123" onmouseover=alert(1)</span>
→ <span class="hl-var">123 onmouseover=alert(1)</span>  <span class="hl-comment">← " 被删除</span>

<span class="hl-comment">// 方式2：标签注入 — ❌ 被过滤</span>
p1=<span class="hl-inject">&lt;img src=x onerror=alert(1)&gt;</span>
→ <span class="hl-var">img src=x onerror=alert(1)</span>  <span class="hl-comment">← &lt;&gt; 被删除</span>

<span class="hl-comment">// 方式3：反引号闭合 — ✅ IE 浏览器可用！</span>
p1=<span class="hl-inject">123`onmouseover=alert(document.domain)</span>
→ <span class="hl-var">123`onmouseover=alert(document.domain)</span>  <span class="hl-comment">← 不含被过滤字符</span></div>
      <p>反引号 <code>`</code> 既不是双引号，也不是尖括号，完美绕过了过滤。而 IE 浏览器恰好支持用反引号作为属性值引号，这就是本关的<strong>唯一突破口</strong>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例5：IE 与现代浏览器的差异总结</h3>
      <p>旧版 IE 浏览器存在大量与现代浏览器不同的解析行为：</p>
      <ul>
        <li><strong>反引号作为引号：</strong>IE6/7 支持 <code>`</code> 包裹属性值，现代浏览器不会</li>
        <li><strong>条件注释：</strong>IE9 及以下支持 <code>&lt;!--[if IE]&gt;...&lt;![endif]--&gt;</code></li>
        <li><strong>CSS expression()：</strong>IE6/7 支持在 CSS 中执行 JS</li>
        <li><strong>SVG CDATA：</strong>IE9/10 对 CDATA 段落处理存在差异</li>
      </ul>
      <p>本关的价值在于<strong>理解浏览器差异导致的安全漏洞</strong>，以及为什么在安全防护中不能只考虑标准行为，还需要考虑各种浏览器的特殊解析方式。</p>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果开发者在过滤中同时去掉了反引号 <code>`</code>，还有其他绕过方式吗？</p>
      <p><strong>答：</strong>在 IE6/7 环境下，如果只过滤了双引号和反引号，还可以利用：</p>
      <ul>
        <li><strong>单引号：</strong>如果单引号也没有被过滤，可以直接用 <code>'</code> 闭合 value</li>
        <li><strong>全角引号：</strong>某些情况下 IE 可能接受全角引号（<code>"</code> <code>"</code>）作为属性分隔符</li>
        <li><strong>空格/Tab 终止：</strong>如果 value 没有引号，空格本身就能终止属性值，无需任何引号</li>
      </ul>
      <p>最佳防御方式是：<strong>始终用双引号包裹属性值</strong> + <strong>使用 <code>htmlspecialchars()</code> 对输出进行编码</strong>，从根本上杜绝属性注入。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
