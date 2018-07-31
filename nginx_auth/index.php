<?php

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

?>

您好！<p>

您从校外访问<?php echo $_REQUEST["next"]; ?>，需要先登录。<p>

请单击<a href="login.php?next=<?php echo $_REQUEST["next"];?>">登录</a>，输入统一身份认证的用户名、密码，会继续下一步访问。


