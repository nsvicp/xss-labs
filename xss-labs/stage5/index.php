<?php
/**
 * XSS Challenges - Stage #5
 * 14.1 限制输入长度的解决方式
 * 
 * 漏洞成因：
 *   服务端限制了输入框的最大长度为 15 个字符
 *   需要使用 BurpSuite 等工具截包修改参数
 * 
 * 通关 Payload：
 *   （使用工具修改）
 *   "><script>alert(document.domain);</script> (16字符)
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #5</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #5</span>
  <h1>限制输入长度的解决方式</h1>
  <span class="difficulty">难度：★★★☆☆ 中级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">前端限制了输入长度为 15 个字符。</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第五关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" placeholder="请输入搜索内容…" autocomplete="off" maxlength="15" />
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?><b><?php echo $p1; ?></b><?php else: ?><span class="result-empty">暂无搜索记录</span><?php endif; ?>
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
      <p>本关服务端的核心漏洞代码如下：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1，无任何过滤</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// 直接拼接到 HTML 输出，未调用 htmlspecialchars()</span>
<span class="hl-php">echo</span> <span class="hl-str">"&lt;b&gt;"</span> . <span class="hl-var">$p1</span> . <span class="hl-str">"&lt;/b&gt;"</span>;</div>
      <p>从服务端角度看，本关与第一关完全相同——p1 参数无任何过滤直接输出。区别仅在于前端 HTML 对输入框做了长度限制：</p>
      <div class="code-block"><span class="hl-comment">&lt;!-- 前端 HTML 属性限制 --&gt;</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">type</span>=<span class="hl-val">"text"</span> <span class="hl-attr">name</span>=<span class="hl-val">"p1"</span> <span class="hl-attr">maxlength</span>=<span class="hl-val">"15"</span> <span class="hl-tag">/&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例1：前端限制的本质</h3>
      <p><code>maxlength="15"</code> 只是 HTML 的客户端属性，浏览器会阻止用户在输入框中输入超过 15 个字符。但这个限制<strong>仅存在于用户的浏览器端</strong>，服务端完全不知情。</p>
      <p>因此，攻击者只需绕过浏览器直接向服务端发送请求即可。标准的 XSS Payload 长度为：</p>
      <div class="code-block"><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span> <span class="hl-comment">← 45 个字符，远超 15 字符限制</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例2：使用 BurpSuite 截包修改参数</h3>
      <p>绕过方式如下：</p>
      <ul>
        <li>在搜索框中随意输入（如 <code>test</code>），点击搜索</li>
        <li>BurpSuite 拦截到请求：<code>stage5.php?p1=test</code></li>
        <li>将 <code>p1</code> 参数值修改为：<code>&lt;script&gt;alert(document.domain);&lt;/script&gt;</code></li>
        <li>放行请求，服务端直接输出注入的脚本</li>
      </ul>
      <p>最终服务端输出：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例3：其他绕过前端限制的方式</h3>
      <p>除了 BurpSuite，还有多种方式可以绕过前端限制：</p>
      <ul>
        <li><strong>浏览器开发者工具：</strong>F12 打开控制台，直接修改 input 的 maxlength 属性为 <code>999</code>，再输入 Payload</li>
        <li><strong>URL 直接构造：</strong>在浏览器地址栏直接访问 <code>stage5.php?p1=&lt;script&gt;alert(document.domain);&lt;/script&gt;</code></li>
        <li><strong>curl/Postman：</strong>使用命令行工具直接发送 HTTP 请求，完全绕过浏览器</li>
        <li><strong>JavaScript 控制台：</strong>修改表单的 action 或直接用 <code>fetch()</code> 发送请求</li>
      </ul>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>既然前端限制可以被轻松绕过，那前端限制还有存在的意义吗？</p>
      <p><strong>答：</strong>前端限制的意义在于<strong>用户体验</strong>而非<strong>安全防护</strong>。例如限制手机号为 11 位、限制密码最小长度等，是为了引导用户正确输入。但涉及安全的场景中，<strong>永远不能依赖前端验证</strong>——服务端必须进行独立的校验和过滤，因为攻击者可以完全控制客户端发送的请求内容。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
