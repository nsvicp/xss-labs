<?php
/**
 * XSS Challenges - Stage #3
 * 13.2.3 选择列表中的 XSS 注入
 *
 * 漏洞成因：
 *   p2 参数被直接输出到 <b> 标签中，无任何过滤
 *   可直接注入 <script> 标签执行
 *
 * 通关 Payload：
 *   p2=<script>alert(document.domain);</script>
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$p2 = isset($_GET['p2']) ? $_GET['p2'] : '';
$searched = isset($_GET['p1']) || isset($_GET['p2']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #3</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #3</span>
  <h1>选择列表中的 XSS 注入</h1>
  <span class="difficulty">难度：★★☆☆☆ 初级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在页面中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>搜索框参数 <code style="color:#e94560;">p1</code> 已做安全过滤，尝试从下拉菜单参数 <code style="color:#e94560;">p2</code> 入手，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">p2 参数被直接输出到 b 标签中，无任何过滤，可直接注入：p2=&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第三关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span>&amp;<span class="url-key">p2</span>=<span class="url-val"><?php echo htmlspecialchars($p2, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <form class="search-form" method="GET" action="">
      <input type="text" name="p1" value="<?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?>" placeholder="请输入搜索内容…" autocomplete="off" />
      <select name="p2">
        <option value="">-- 请选择语言 --</option>
        <option value="Chinese" <?php if ($p2 === 'Chinese') echo 'selected'; ?>>Chinese</option>
        <option value="English" <?php if ($p2 === 'English') echo 'selected'; ?>>English</option>
      </select>
      <button type="submit">搜索</button>
    </form>
    <div class="result-area">
      <div class="result-label">搜索结果</div>
      <div class="result-text">
        <?php if ($searched): ?>
          <p><strong>p1 搜索内容：</strong><b><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></b></p>
          <p><strong>p2 选择结果：</strong><b><?php echo $p2; ?></b></p>
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
      <div class="code-block"><span class="hl-comment">// 获取参数</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;
<span class="hl-var">$p2</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p2'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p2'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// ✅ p1：使用 htmlspecialchars 安全输出到 &lt;b&gt; 标签</span>
<span class="hl-tag">&lt;b&gt;</span>&lt;?php echo <span class="hl-php">htmlspecialchars</span>(<span class="hl-var">$p1</span>, <span class="hl-str">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>); ?&gt;<span class="hl-tag">&lt;/b&gt;</span>

<span class="hl-comment">// ❌ p2：直接输出到 &lt;b&gt; 标签，无任何过滤（漏洞点）</span>
<span class="hl-tag">&lt;b&gt;</span>&lt;?php echo <span class="hl-var">$p2</span>; ?&gt;<span class="hl-tag">&lt;/b&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>例1：直接注入 Script 标签</h3>
      <p>p2 参数的值被直接回显到搜索结果的 <code>&lt;b&gt;</code> 标签中，无任何过滤。直接构造 URL：</p>
      <div class="code-block">stage3.php?p1=test&amp;p2=<span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>服务端将 p2 直接输出到 <code>&lt;b&gt;</code> 标签中：</p>
      <div class="code-block"><span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">&lt;script&gt;alert(document.domain);&lt;/script&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
      <p>注入的 <code>&lt;script&gt;</code> 标签被浏览器独立解析执行，弹出 alert 对话框。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：p1 参数为什么无法注入？</h3>
      <p>p1 使用了 <code>htmlspecialchars($p1, ENT_QUOTES, 'UTF-8')</code> 进行输出编码：</p>
      <div class="code-block"><span class="hl-comment">// 用户输入 &lt;script&gt; 会被编码为 &amp;lt;script&amp;gt;</span>
<span class="hl-php">echo</span> <span class="hl-php">htmlspecialchars</span>(<span class="hl-str">'&lt;script&gt;alert(1)&lt;/script&gt;'</span>, <span class="hl-str">ENT_QUOTES</span>, <span class="hl-str">'UTF-8'</span>);
<span class="hl-comment">// 输出：&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;</span></div>
      <p>浏览器将其作为普通文本渲染，<code>&lt;script&gt;</code> 不会被执行。关键对比：</p>
      <table style="width:100%; margin:10px 0; border-collapse:collapse; font-size:13px;">
        <tr style="background:#f0f4f8;">
          <th style="padding:8px; border:1px solid #ddd; text-align:left;">参数</th>
          <th style="padding:8px; border:1px solid #ddd; text-align:left;">过滤方式</th>
          <th style="padding:8px; border:1px solid #ddd; text-align:left;">是否存在 XSS</th>
        </tr>
        <tr>
          <td style="padding:8px; border:1px solid #ddd;">p1（搜索框）</td>
          <td style="padding:8px; border:1px solid #ddd;">htmlspecialchars</td>
          <td style="padding:8px; border:1px solid #ddd; color:green;">✅ 安全</td>
        </tr>
        <tr>
          <td style="padding:8px; border:1px solid #ddd;">p2（下拉菜单）</td>
          <td style="padding:8px; border:1px solid #ddd;">无过滤</td>
          <td style="padding:8px; border:1px solid #ddd; color:red;">❌ 存在漏洞</td>
        </tr>
      </table>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果 p2 输出到 <code>&lt;input value="&lt;?php echo $p2; ?&gt;"&gt;</code> 属性中，payload 需要怎么调整？</p>
      <p><strong>答：</strong>需要先闭合 value 属性的双引号和 input 标签：</p>
      <div class="code-block">p2=<span class="hl-inject">&quot;&gt;&lt;script&gt;alert(document.domain);&lt;/script&gt;</span></div>
      <p>核心原则：分析用户输入在 HTML 中的<strong>上下文位置</strong>（属性值 vs 文本内容），然后决定需要闭合哪些字符或标签。本关中 p2 输出在 <code>&lt;b&gt;</code> 标签的文本内容中，因此只需要直接注入 HTML 标签即可。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
