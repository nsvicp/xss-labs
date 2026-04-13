<?php
/**
 * XSS Challenges - 靶场首页
 */

// 关卡数据定义
$stages = [
    [
        'id'         => 1,
        'title'      => '无过滤的 XSS 注入',
        'desc'       => '用户输入直接拼接到 HTML 中输出，无任何过滤。掌握反射型 XSS 的最基础注入方式。',
        'difficulty' => 1,
        'tag'        => '反射型',
        'tag_color'  => '#e94560',
        'file'       => 'xss-labs/stage1/',
    ],
    [
        'id'         => 2,
        'title'      => '属性中的 XSS 注入',
        'desc'       => '用户输入被嵌入到 HTML 标签属性中，需要通过闭合属性引号来逃逸并注入脚本。',
        'difficulty' => 2,
        'tag'        => '属性注入',
        'tag_color'  => '#f5a623',
        'file'       => 'xss-labs/stage2/',
    ],
    [
        'id'         => 3,
        'title'      => '选择列表中的 XSS 注入',
        'desc'       => '用户输入被插入到 select 标签的 option 中，需要闭合标签后才能注入脚本。',
        'difficulty' => 2,
        'tag'        => '属性注入',
        'tag_color'  => '#f5a623',
        'file'       => 'xss-labs/stage3/',
    ],
    [
        'id'         => 4,
        'title'      => '在隐藏域中注入 XSS',
        'desc'       => '用户输入被插入到隐藏域（type="hidden"）中，需要查看源代码并闭合标签。',
        'difficulty' => 2,
        'tag'        => '属性注入',
        'tag_color'  => '#f5a623',
        'file'       => 'xss-labs/stage4/',
    ],
    [
        'id'         => 5,
        'title'      => '限制输入长度的解决方式',
        'desc'       => '前端限制了输入长度，需要使用 BurpSuite 等工具截包修改参数绕过。',
        'difficulty' => 3,
        'tag'        => '长度绕过',
        'tag_color'  => '#7c3aed',
        'file'       => 'xss-labs/stage5/',
    ],
    [
        'id'         => 6,
        'title'      => '限制输入<>的 XSS 注入',
        'desc'       => '服务端过滤了 < 和 > 字符，需要使用事件属性绕过。',
        'difficulty' => 3,
        'tag'        => '过滤绕过',
        'tag_color'  => '#7c3aed',
        'file'       => 'xss-labs/stage6/',
    ],
    [
        'id'         => 7,
        'title'      => '限制输入引号的 XSS 注入',
        'desc'       => '服务端过滤了引号，需要闭合 script 标签绕过。',
        'difficulty' => 3,
        'tag'        => '过滤绕过',
        'tag_color'  => '#7c3aed',
        'file'       => 'xss-labs/stage7/',
    ],
    [
        'id'         => 8,
        'title'      => 'JavaScript 伪协议',
        'desc'       => '用户输入被插入到 a 标签的 href 属性中，使用 javascript: 伪协议执行脚本。',
        'difficulty' => 3,
        'tag'        => '伪协议',
        'tag_color'  => '#0891b2',
        'file'       => 'xss-labs/stage8/',
    ],
    [
        'id'         => 9,
        'title'      => 'UTF-7 编码注入（已跳过）',
        'desc'       => 'UTF-7 编码绕过，现代浏览器已废弃此特性，本关不再实现。',
        'difficulty' => 0,
        'tag'        => '已跳过',
        'tag_color'  => '#6b7280',
        'file'       => 'xss-labs/stage9/',
    ],
    [
        'id'         => 10,
        'title'      => '绕过关键字 domain',
        'desc'       => '服务端过滤了 "domain" 关键字，可以使用双写或数组方式绕过。',
        'difficulty' => 4,
        'tag'        => '关键字绕过',
        'tag_color'  => '#7c3aed',
        'file'       => 'xss-labs/stage10/',
    ],
    [
        'id'         => 11,
        'title'      => '绕过多条正则过滤规则',
        'desc'       => '服务端使用三条正则过滤了 script、on事件属性 和 style=，可以通过 HTML 空白字符绕过。',
        'difficulty' => 4,
        'tag'        => '正则绕过',
        'tag_color'  => '#7c3aed',
        'file'       => 'xss-labs/stage11/',
    ],
    [
        'id'         => 12,
        'title'      => '利用 IE 浏览器特性绕过',
        'desc'       => '利用 IE 条件注释语法，在旧版 IE 浏览器中执行脚本。',
        'difficulty' => 5,
        'tag'        => 'IE 特性',
        'tag_color'  => '#dc2626',
        'file'       => 'xss-labs/stage12/',
    ],
    [
        'id'         => 13,
        'title'      => 'CSS IE 特性伪协议注入',
        'desc'       => 'IE 浏览器支持在 CSS 中使用 expression 表达式执行脚本。',
        'difficulty' => 5,
        'tag'        => 'IE 特性',
        'tag_color'  => '#dc2626',
        'file'       => 'xss-labs/stage13/',
    ],
    [
        'id'         => 14,
        'title'      => 'CSS 内联注释注入',
        'desc'       => '利用 IE 浏览器的 CSS 解析缺陷，通过内联注释绕过过滤。',
        'difficulty' => 5,
        'tag'        => 'IE 特性',
        'tag_color'  => '#dc2626',
        'file'       => 'xss-labs/stage14/',
    ],
    [
        'id'         => 15,
        'title'      => '十六进制绕过',
        'desc'       => '利用 JavaScript 十六进制转义序列（\\x3c）绕过 document.write 的 <> 过滤。',
        'difficulty' => 4,
        'tag'        => '编码绕过',
        'tag_color'  => '#0891b2',
        'file'       => 'xss-labs/stage15/',
    ],
    [
        'id'         => 16,
        'title'      => 'Unicode 绕过',
        'desc'       => 'Stage 15 升级防御：\\x 被转义为 \\\\x，但遗漏了 \\u Unicode 转义，可以用 \\u003c 绕过。',
        'difficulty' => 5,
        'tag'        => '编码绕过',
        'tag_color'  => '#0891b2',
        'file'       => 'xss-labs/stage16/',
    ],
];

// 难度星级渲染
function renderStars(int $n): string {
    $filled = str_repeat('★', $n);
    $empty  = str_repeat('☆', 5 - $n);
    return $filled . $empty;
}
?>
<!DOCTYPE html>
<!--[if lt IE 9]><html class="ie-old" lang="zh-CN"><![endif]-->
<!--[if gte IE 9]><!--><html lang="zh-CN"><!--<![endif]-->
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>XSS Challenges - 靶场首页</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
      font-size: 14px;
      background: #f0f4f8;
      color: #333;
      min-height: 100%;
    }

    /* ===== Header ===== */
    header {
      background: #1a1a2e; /* IE fallback */
      background: -ms-linear-gradient(315deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
      color: #fff;
      padding: 0 40px;
      height: 60px;
      line-height: 60px;
      position: relative;
      z-index: 100;
      /* IE fallback: no sticky */
      zoom: 1;
    }
    /* clearfix for IE */
    header:after { content: ''; display: table; clear: both; }

    .logo {
      font-size: 22px;
      font-weight: bold;
      letter-spacing: 2px;
      color: #e94560;
      text-decoration: none;
      display: inline-block;
      vertical-align: middle;
      line-height: normal;
      margin-top: 14px;
    }
    .logo .dot { color: #a8dadc; }

    /* ===== Hero Banner ===== */
    .hero {
      background: #0f3460; /* IE fallback */
      background: -ms-linear-gradient(315deg, #0f3460 0%, #533483 60%, #16213e 100%);
      background: linear-gradient(135deg, #0f3460 0%, #533483 60%, #16213e 100%);
      color: #fff;
      padding: 56px 40px 48px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }

    .hero h1 {
      font-size: 38px;
      font-weight: 900;
      letter-spacing: 3px;
      margin-bottom: 16px;
    }

    .hero h1 em {
      font-style: normal;
      color: #e94560;
    }

    .hero p {
      font-size: 15px;
      color: #a8dadc;
      max-width: 560px;
      margin: 0 auto;
      line-height: 1.8;
    }

    /* ===== Main ===== */
    main {
      max-width: 1100px;
      width: 100%;
      margin: 40px auto;
      padding: 0 28px;
      zoom: 1;
    }
    main:after { content: ''; display: table; clear: both; }

    .section-header {
      margin-bottom: 24px;
      zoom: 1;
    }
    .section-header:after { content: ''; display: table; clear: both; }

    .section-header h2 {
      font-size: 20px;
      font-weight: bold;
      color: #0f3460;
      display: inline-block;
      vertical-align: middle;
    }

    .section-header .count {
      background: #e94560;
      color: #fff;
      font-size: 12px;
      font-weight: bold;
      padding: 2px 10px;
      border-radius: 20px;
      display: inline-block;
      vertical-align: middle;
      margin-left: 10px;
    }

    /* ===== 关卡卡片网格（IE 兼容 float 布局）===== */
    .stages-grid {
      zoom: 1;
    }
    .stages-grid:after { content: ''; display: table; clear: both; }

    .stage-card {
      background: #fff;
      border-radius: 10px;
      border: 1px solid #eef1f6;
      overflow: hidden;
      float: left;
      width: 31.5%;
      margin-right: 2.5%;
      margin-bottom: 20px;
      vertical-align: top;
      /* IE box-shadow fallback */
      -ms-filter: "progid:DXImageTransform.Microsoft.Shadow(color=#cccccc,Direction=135,Strength=5)";
      filter: progid:DXImageTransform.Microsoft.Shadow(color=#cccccc,Direction=135,Strength=5);
      box-shadow: 0 2px 12px rgba(0,0,0,0.07);
    }
    /* 每3个卡片后清除float */
    .stage-card:nth-child(3n) { margin-right: 0; }

    /* IE8 不支持 nth-child，用 class 辅助 */
    .stage-card.last-in-row { margin-right: 0; }

    /* ===== 卡片头部 ===== */
    .stage-card .card-head {
      padding: 18px 20px 14px;
      border-bottom: 1px solid #f0f4f8;
      zoom: 1;
    }
    .stage-card .card-head:after { content: ''; display: table; clear: both; }

    .stage-num {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: #0f3460; /* IE fallback */
      background: -ms-linear-gradient(315deg, #0f3460, #533483);
      background: linear-gradient(135deg, #0f3460, #533483);
      color: #fff;
      font-size: 15px;
      font-weight: bold;
      text-align: center;
      line-height: 40px;
      float: left;
      margin-right: 14px;
    }

    .card-title-wrap {
      overflow: hidden; /* BFC，配合 float */
    }

    .card-title {
      font-size: 15px;
      font-weight: bold;
      color: #1a1a2e;
      margin-bottom: 6px;
      line-height: 1.4;
    }

    .card-tags {
      zoom: 1;
    }
    .card-tags:after { content: ''; display: table; clear: both; }

    .tag {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 12px;
      font-weight: bold;
      color: #fff;
      display: inline-block;
      margin-right: 6px;
      margin-bottom: 4px;
    }

    .tag-difficulty {
      font-size: 11px;
      color: #f5a623;
      letter-spacing: 1px;
      display: inline-block;
    }

    /* 卡片内容 */
    .card-body {
      padding: 14px 20px;
    }

    .card-desc {
      font-size: 13px;
      color: #666;
      line-height: 1.7;
    }

    /* 卡片底部 */
    .card-footer {
      padding: 14px 20px;
      border-top: 1px solid #f0f4f8;
      text-align: right;
      zoom: 1;
    }

    .btn-start {
      display: inline-block;
      background: #e94560;
      color: #fff;
      text-decoration: none;
      font-size: 13px;
      font-weight: bold;
      padding: 8px 18px;
      border-radius: 6px;
    }

    .btn-start:hover { background: #c73652; }

    .btn-start.locked {
      background: #ccc;
      cursor: not-allowed;
    }

    /* ===== Footer ===== */
    #footer {
      background: #1a1a2e;
      color: #555;
      text-align: center;
      padding: 20px;
      font-size: 12px;
      line-height: 1.8;
      clear: both;
    }

    #footer span { color: #a8dadc; }

    /* header id */
    #header {
      background: #1a1a2e;
      background: -ms-linear-gradient(315deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
      color: #fff;
      padding: 0 40px;
      height: 60px;
      line-height: 60px;
      position: relative;
      z-index: 100;
      zoom: 1;
    }

    /* main id */
    #main {
      max-width: 1100px;
      width: 100%;
      margin: 40px auto;
      padding: 0 28px;
      zoom: 1;
    }
    #main:after { content: ''; display: table; clear: both; }

    /* ===== 响应式（现代浏览器）===== */
    @media (max-width: 900px) {
      .stage-card { width: 48%; margin-right: 4%; }
      .stage-card:nth-child(3n) { margin-right: 4%; }
      .stage-card:nth-child(2n) { margin-right: 0; }
    }
    @media (max-width: 560px) {
      .stage-card { width: 100%; margin-right: 0; float: none; }
    }
  </style>
</head>
<body>

<!-- Header -->
<div id="header">
  <a class="logo" href="index.php">
    极客事纪 XSS<span class="dot">·</span>Challenges靶场
  </a>
</div>

<!-- Hero -->
<div class="hero">
  <h1>极客事纪 XSS <em>Challenges</em>靶场</h1>
  <p>通过闯关式练习，系统掌握跨站脚本攻击（XSS）的各种注入技巧与防御方法。</p>
</div>

<div id="main">
  <!-- 关卡列表 -->
  <div class="section-header">
    <h2>全部关卡</h2>
    <span class="count"><?php echo count($stages); ?></span>
  </div>

  <div class="stages-grid">
    <?php foreach ($stages as $s): ?>
      <?php
        $isOpen       = $s['file'] !== 'xss-labs/stage9/';
        $cardClass    = 'stage-card';
        if (!$isOpen)  $cardClass .= ' coming-soon';
      ?>
      <div class="<?php echo $cardClass; ?>">
        <div class="card-head">
          <div class="stage-num"><?php echo $s['id']; ?></div>
          <div class="card-title-wrap">
            <div class="card-title"><?php echo htmlspecialchars($s['title'], ENT_QUOTES, 'UTF-8'); ?></div>
            <div class="card-tags">
              <span class="tag" style="background:<?php echo $s['tag_color']; ?>">
                <?php echo htmlspecialchars($s['tag'], ENT_QUOTES, 'UTF-8'); ?>
              </span>
              <span class="tag-difficulty"><?php echo renderStars($s['difficulty']); ?></span>
            </div>
          </div>
        </div>

        <div class="card-body">
          <p class="card-desc"><?php echo htmlspecialchars($s['desc'], ENT_QUOTES, 'UTF-8'); ?></p>
        </div>

        <div class="card-footer">
          <?php if ($isOpen): ?>
            <a class="btn-start" href="<?php echo htmlspecialchars($s['file'], ENT_QUOTES, 'UTF-8'); ?>">
              &#9654; 开始挑战
            </a>
          <?php else: ?>
            <a class="btn-start locked" href="#">&#128274; 即将开放</a>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>

</div>

<div id="footer">
  极客事纪 XSS Challenges靶场 &nbsp;·&nbsp; 仅供 <span>安全学习与研究</span> 使用，请勿用于非法用途
</div>

</body>
</html>
