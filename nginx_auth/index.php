<?php

$auth_key = "changeme";

session_start();

if(isset($_SESSION['uid'])) 
	$auth_uid=$_SESSION['uid'];
else {
	require_once('USTC_CAS.php');
    	$cas = ustc_cas_login();
    	$user = $cas->user();
    	$gid = $cas->gid();
    	$_SESSION['uid']=$user;
    	$auth_uid=$user;
}

$expire_time = time()+3600*30;

setcookie("nginx_auth_uid", $auth_uid, $expire_time, "/", $_SERVER['HTTP_HOST']);
setcookie("nginx_auth_expire", $expire_time, $expire_time, "/", $_SERVER['HTTP_HOST']);
setcookie("nginx_auth_hash", md5($auth_key."|".$auth_uid."|".$expire_time."|"), $expire_time, "/", $_SERVER['HTTP_HOST']);

echo "hello $user<p>";

$next=$_REQUEST["next"];
echo "you are logged in, please go <a href=$next>$next</a>.";
?>
