--TEST--
Bug #71683 Null pointer dereference in zend_hash_str_find_bucket
--EXTENSIONS--
session
--SKIPIF--
<?php include('skipif.inc'); ?>
--INI--
session.save_handler=files
session.auto_start=1
session.use_only_cookies=0
--FILE--
<?php
ob_start();
echo "ok\n";
?>
--EXPECT--
Deprecated: PHP Startup: Disabling session.use_only_cookies INI setting is deprecated in Unknown on line 0
ok
