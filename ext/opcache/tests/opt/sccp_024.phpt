--TEST--
SCCP 024: Const replacing to op2 of INSTANCEOF
--INI--
opcache.enable=1
opcache.enable_cli=1
opcache.optimization_level=-1
opcache.opt_debug_level=0x20000
opcache.preload=
--SKIPIF--
<?php require_once('skipif.inc'); ?>
--FILE--
<?php
class A {
	function t($obj) {
		$a = "A";
        $b = "self";
        $c = 1;
        echo ($obj instanceof $a);
        echo ($obj instanceof $b);
        echo ($obj instanceof $c);
	}
}
?>
--EXPECTF--
$_main: ; (lines=1, args=0, vars=0, tmps=0)
    ; (after optimizer)
    ; %ssccp_024.php:1-13
L0 (13):    RETURN int(1)

A::t: ; (lines=11, args=1, vars=2, tmps=2)
    ; (after optimizer)
    ; %ssccp_024.php:3-10
L0 (3):     ENTER 0 1 2
L1 (3):     CV0($obj) = RECV 1
L2 (6):     CV1($c) = QM_ASSIGN int(1)
L3 (7):     T2 = INSTANCEOF CV0($obj) string("A")
L4 (7):     ECHO T2
L5 (8):     T2 = INSTANCEOF CV0($obj) string("self")
L6 (8):     ECHO T2
L7 (9):     V3 = FETCH_CLASS (no-autolod) (exception) CV1($c)
L8 (9):     T2 = INSTANCEOF CV0($obj) V3
L9 (9):     ECHO T2
L10 (10):   RETURN null
