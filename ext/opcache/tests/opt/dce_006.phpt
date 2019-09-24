--TEST--
DCE 006: Objects with destructors escape
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
	function __destruct() {}
}
function foo(int $x) {
	$a = new A;
	$a->foo = $x;
}
--EXPECTF--
$_main: ; (lines=1, args=0, vars=0, tmps=0)
    ; (after optimizer)
    ; %sdce_006.php:1-9
L0 (9):     RETURN int(1)

foo: ; (lines=8, args=1, vars=2, tmps=1)
    ; (after optimizer)
    ; %sdce_006.php:5-8
L0 (5):     ENTER 1 1 2
L1 (5):     CV0($x) = RECV 1
L2 (6):     V2 = NEW 0 string("A")
L3 (6):     DO_FCALL
L4 (6):     CV1($a) = QM_ASSIGN V2
L5 (7):     ASSIGN_OBJ CV1($a) string("foo")
L6 (7):     OP_DATA CV0($x)
L7 (8):     RETURN null
LIVE RANGES:
        2: L3 - L4 (new)

A::__destruct: ; (lines=2, args=0, vars=0, tmps=0)
    ; (after optimizer)
    ; %sdce_006.php:3-3
L0 (3):     ENTER 0 0 0
L1 (3):     RETURN null
