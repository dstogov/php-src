/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2015 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

#include "zend.h"
#include "zend_virtual_cwd.h"
#include "zend_compile.h"
#include "zend_vm.h"

#include "php.h"

#include "ZendAccelerator.h"
#include "zend_permanent.h"
#include "zend_shared_alloc.h"
#include "zend_accelerator_util_funcs.h"
#include "zend_accelerator_hash.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#define SUFFIX ".bin"

#define IS_SERIALIZED_INTERNED(ptr) \
	((size_t)(ptr) & Z_UL(1))
#define IS_SERIALIZED(ptr) \
	((char*)(ptr) < (char*)script->size)
#define IS_UNSERIALIZED(ptr) \
	(((char*)(ptr) >= (char*)script->mem && (char*)(ptr) < (char*)script->mem + script->size) || \
	 IS_ACCEL_INTERNED(ptr))
#define SERIALIZE_PTR(ptr) do { \
		if (ptr) { \
			if (IS_ACCEL_INTERNED(ptr)) { \
				(ptr) = zend_permanent_serialize_interned((zend_string*)(ptr), info); \
			} else { \
				ZEND_ASSERT(IS_UNSERIALIZED(ptr)); \
				(ptr) = (void*)((char*)(ptr) - (char*)script->mem); \
			} \
		} \
	} while (0)
#define UNSERIALIZE_PTR(ptr) do { \
		if (ptr) { \
			if (IS_SERIALIZED_INTERNED(ptr)) { \
				(ptr) = (void*)zend_permanent_unserialize_interned((zend_string*)(ptr), info); \
			} else { \
				ZEND_ASSERT(IS_SERIALIZED(ptr)); \
				(ptr) = (void*)((char*)buf + (size_t)(ptr)); \
			} \
		} \
	} while (0)

static const uint32_t uninitialized_bucket[-HT_MIN_MASK] =
	{HT_INVALID_IDX, HT_INVALID_IDX};

typedef struct _zend_permanent_metainfo {
	char   magic[8];
	size_t mem_size;
	size_t str_size;
	size_t script_offset;
	union {
		zend_string *strings;
		char        *chars;
		uint32_t     checksum;
	} u;
} zend_permanent_metainfo;

static int zend_permanent_mkdir(char *filename, size_t start)
{
	char *s = filename + start;

	while (*s) {
		if (IS_SLASH(*s)) {
			char old = *s;
			*s = '\000';
			if (mkdir(filename, S_IRWXU) < 0 && errno != EEXIST) {
				*s = old;
				return FAILURE;
			}
			*s = old;
		}
		s++;
	}
	return SUCCESS;
}

typedef void (*serialize_callback_t)(zval                    *zv,
                                     zend_persistent_script  *script,
                                     zend_permanent_metainfo *info,
                                     void                    *buf);

typedef void (*unserialize_callback_t)(zval                    *zv,
                                       zend_persistent_script  *script,
                                       zend_permanent_metainfo *info,
                                       void                    *buf);

static void zend_permanent_serialize_zval(zval                    *zv,
                                          zend_persistent_script  *script,
                                          zend_permanent_metainfo *info,
                                          void                    *buf);
static void zend_permanent_unserialize_zval(zval                    *zv,
                                            zend_persistent_script  *script,
                                            zend_permanent_metainfo *info,
                                            void                    *buf);

static void *zend_permanent_serialize_interned(zend_string             *str,
                                               zend_permanent_metainfo *info)
{
	size_t len;
	void *ret;

	/* check if the same interned string was already stored */
	ret = zend_shared_alloc_get_xlat_entry(str);
	if (ret) {
		return ret;
	}

	len = ZEND_MM_ALIGNED_SIZE(_STR_HEADER_SIZE + str->len + 1);
	ret = (void*)(info->str_size | Z_UL(1));
	zend_shared_alloc_register_xlat_entry(str, ret);
	if (info->str_size + len > info->u.strings->len) {
		//TODO: improve reallocation granularity???
		size_t new_len = info->str_size + len;
		info->u.strings = zend_string_realloc(info->u.strings, new_len, 0);
	}
	memcpy(info->u.strings->val + info->str_size, str, len);
	info->str_size += len;
	return ret;
}

static void *zend_permanent_unserialize_interned(zend_string             *str,
                                                 zend_permanent_metainfo *info)
{
	zend_string *ret;

	str = (zend_string*)((char*)info->u.chars + ((size_t)(str) & ~Z_UL(1)));
	ret = accel_new_interned_string(str);
	//TODO: what if it fails ???
	ZEND_ASSERT(ret && ret != str);
	return ret;
}

static void zend_permanent_serialize_hash(HashTable               *ht,
                                          zend_persistent_script  *script,
                                          zend_permanent_metainfo *info,
                                          void                    *buf,
                                          serialize_callback_t     func)
{
	Bucket *p, *end;

	if (!(ht->u.flags & HASH_FLAG_INITIALIZED)) {
		ht->arData = NULL;
		return;
	}
	if (IS_SERIALIZED(ht->arData)) {
		return;
	}
	SERIALIZE_PTR(ht->arData);
	p = ht->arData;
	UNSERIALIZE_PTR(p);
	end = p + ht->nNumUsed;
	while (p < end) {
		if (Z_TYPE(p->val) != IS_UNDEF) {
			SERIALIZE_PTR(p->key);
			func(&p->val, script, info, buf);
		}
		p++;
	}
}

static zend_ast *zend_permanent_serialize_ast(zend_ast                *ast,
                                              zend_persistent_script  *script,
                                              zend_permanent_metainfo *info,
                                              void                    *buf)
{
	uint32_t i;
	zend_ast *ret;

	SERIALIZE_PTR(ast);
	ret = ast;
	UNSERIALIZE_PTR(ast);

	if (ast->kind == ZEND_AST_ZVAL) {
		zend_permanent_serialize_zval(&((zend_ast_zval*)ast)->val, script, info, buf);
	} else if (zend_ast_is_list(ast)) {
		zend_ast_list *list = zend_ast_get_list(ast);
		for (i = 0; i < list->children; i++) {
			if (list->child[i]) {
				list->child[i] = zend_permanent_serialize_ast(list->child[i], script, info, buf);
			}
		}
	} else {
		uint32_t children = zend_ast_get_num_children(ast);
		for (i = 0; i < children; i++) {
			if (ast->child[i]) {
				ast->child[i] = zend_permanent_serialize_ast(ast->child[i], script, info, buf);
			}
		}
	}
	return ret;
}

static void zend_permanent_serialize_zval(zval                    *zv,
                                          zend_persistent_script  *script,
                                          zend_permanent_metainfo *info,
                                          void                    *buf)
{
	switch (Z_TYPE_P(zv)) {
		case IS_STRING:
		case IS_CONSTANT:
			if (!IS_SERIALIZED(Z_STR_P(zv))) {
				SERIALIZE_PTR(Z_STR_P(zv));
			}
			break;
		case IS_ARRAY:
			if (!IS_SERIALIZED(Z_ARR_P(zv))) {
				HashTable *ht;

				SERIALIZE_PTR(Z_ARR_P(zv));
				ht = Z_ARR_P(zv);
				UNSERIALIZE_PTR(ht);
				zend_permanent_serialize_hash(ht, script, info, buf, zend_permanent_serialize_zval);
			}
			break;
		case IS_REFERENCE:
			if (!IS_SERIALIZED(Z_REF_P(zv))) {
				zend_reference *ref;

				SERIALIZE_PTR(Z_REF_P(zv));
				ref = Z_REF_P(zv);
				UNSERIALIZE_PTR(ref);
				zend_permanent_serialize_zval(&ref->val, script, info, buf);
			}
			break;
		case IS_CONSTANT_AST:
			if (!IS_SERIALIZED(Z_AST_P(zv))) {
				zend_ast_ref *ast;

				SERIALIZE_PTR(Z_AST_P(zv));
				ast = Z_AST_P(zv);
				UNSERIALIZE_PTR(ast);
				if (!IS_SERIALIZED(ast->ast)) {
					ast->ast = zend_permanent_serialize_ast(ast->ast, script, info, buf);
				}
			}
			break;
	}
}

static void zend_permanent_serialize_op_array(zend_op_array           *op_array,
                                              zend_persistent_script  *script,
                                              zend_permanent_metainfo *info,
                                              void                    *buf)
{
	if (op_array->static_variables && !IS_SERIALIZED(op_array->static_variables)) {
		HashTable *ht;

		SERIALIZE_PTR(op_array->static_variables);
		ht = op_array->static_variables;
		UNSERIALIZE_PTR(ht);
		zend_permanent_serialize_hash(ht, script, info, buf, zend_permanent_serialize_zval);
	}

	if (op_array->literals && !IS_SERIALIZED(op_array->literals)) {
		zval *p, *end;

		SERIALIZE_PTR(op_array->literals);
		p = op_array->literals;
		UNSERIALIZE_PTR(p);
		end = p + op_array->last_literal;
		while (p < end) {
			zend_permanent_serialize_zval(p, script, info, buf);
			p++;
		}
	}

	if (!IS_SERIALIZED(op_array->opcodes)) {
#if ZEND_USE_ABS_CONST_ADDR || ZEND_USE_ABS_JMP_ADDR
		zend_op *opline, *end;

		SERIALIZE_PTR(op_array->opcodes);
		opline = op_array->opcodes;
		UNSERIALIZE_PTR(opline);
		end = opline + op_array->last;
		while (opline < end) {
# if ZEND_USE_ABS_CONST_ADDR
			if (ZEND_OP1_TYPE(opline) == IS_CONST) {
				SERIALIZE_PTR(opline->op1.zv);
			}
			if (ZEND_OP2_TYPE(opline) == IS_CONST) {
				SERIALIZE_PTR(opline->op2.zv);
			}
# endif
# if ZEND_USE_ABS_JMP_ADDR
			switch (opline->opcode) {
				case ZEND_JMP:
				case ZEND_GOTO:
				case ZEND_FAST_CALL:
					SERIALIZE_PTR(opline->op1.jmp_addr);
					break;
				case ZEND_JMPZNZ:
					/* relative extended_value don't have to be changed */
					/* break omitted intentionally */
				case ZEND_JMPZ:
				case ZEND_JMPNZ:
				case ZEND_JMPZ_EX:
				case ZEND_JMPNZ_EX:
				case ZEND_JMP_SET:
				case ZEND_COALESCE:
				case ZEND_NEW:
				case ZEND_FE_RESET_R:
				case ZEND_FE_RESET_RW:
				case ZEND_FE_FETCH_R:
				case ZEND_FE_FETCH_RW:
				case ZEND_ASSERT_CHECK:
					SERIALIZE_PTR(opline->op2.jmp_addr);
					break;
			}
# endif
			opline++;
		}
#else
		SERIALIZE_PTR(op_array->opcodes);
#endif

		if (op_array->arg_info) {
			zend_arg_info *p, *end;
			SERIALIZE_PTR(op_array->arg_info);
			p = op_array->arg_info;
			UNSERIALIZE_PTR(p);
			end = p + op_array->num_args;
			if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
				p--;
			}
			if (op_array->fn_flags & ZEND_ACC_VARIADIC) {
				end++;
			}
			while (p < end) {
				if (!IS_SERIALIZED(p->name)) {
					SERIALIZE_PTR(p->name);
				}
				if (!IS_SERIALIZED(p->class_name)) {
					SERIALIZE_PTR(p->class_name);
				}
				p++;
			}
		}

		if (op_array->vars) {
			zend_string **p, **end;

			SERIALIZE_PTR(op_array->vars);
			p = op_array->vars;
			UNSERIALIZE_PTR(p);
			end = p + op_array->last_var;
			while (p < end) {
				if (!IS_SERIALIZED(*p)) {
					SERIALIZE_PTR(*p);
				}
				p++;
			}
		}

		SERIALIZE_PTR(op_array->function_name);
		SERIALIZE_PTR(op_array->filename);
		SERIALIZE_PTR(op_array->brk_cont_array);
		SERIALIZE_PTR(op_array->scope);
		SERIALIZE_PTR(op_array->doc_comment);
		SERIALIZE_PTR(op_array->try_catch_array);
		SERIALIZE_PTR(op_array->prototype);
	}
}

static void zend_permanent_serialize_func(zval                    *zv,
                                          zend_persistent_script  *script,
                                          zend_permanent_metainfo *info,
                                          void                    *buf)
{
	zend_op_array *op_array;

	SERIALIZE_PTR(Z_PTR_P(zv));
	op_array = Z_PTR_P(zv);
	UNSERIALIZE_PTR(op_array);
	zend_permanent_serialize_op_array(op_array, script, info, buf);
}

static void zend_permanent_serialize_prop_info(zval                    *zv,
                                               zend_persistent_script  *script,
                                               zend_permanent_metainfo *info,
                                               void                    *buf)
{
	if (!IS_SERIALIZED(Z_PTR_P(zv))) {
		zend_property_info *prop;

		SERIALIZE_PTR(Z_PTR_P(zv));
		prop = Z_PTR_P(zv);
		UNSERIALIZE_PTR(prop);

		if (prop->ce && !IS_SERIALIZED(prop->ce)) {
			SERIALIZE_PTR(prop->ce);
		}
		if (prop->name && !IS_SERIALIZED(prop->name)) {
			SERIALIZE_PTR(prop->name);
		}
		if (prop->doc_comment && !IS_SERIALIZED(prop->doc_comment)) {
			SERIALIZE_PTR(prop->doc_comment);
		}
	}
}

static void zend_permanent_serialize_class(zval                    *zv,
                                           zend_persistent_script  *script,
                                           zend_permanent_metainfo *info,
                                           void                    *buf)
{
	zend_class_entry *ce;

	SERIALIZE_PTR(Z_PTR_P(zv));
	ce = Z_PTR_P(zv);
	UNSERIALIZE_PTR(ce);

	SERIALIZE_PTR(ce->name);
	zend_permanent_serialize_hash(&ce->function_table, script, info, buf, zend_permanent_serialize_func);
	if (ce->default_properties_table) {
		zval *p, *end;

		SERIALIZE_PTR(ce->default_properties_table);
		p = ce->default_properties_table;
		UNSERIALIZE_PTR(p);
		end = p + ce->default_properties_count;
		while (p < end) {
			zend_permanent_serialize_zval(p, script, info, buf);
			p++;
		}
	}
	if (ce->default_static_members_table) {
		zval *p, *end;

		SERIALIZE_PTR(ce->default_static_members_table);
		p = ce->default_static_members_table;
		UNSERIALIZE_PTR(p);
		end = p + ce->default_static_members_count;
		while (p < end) {
			zend_permanent_serialize_zval(p, script, info, buf);
			p++;
		}
	}
	zend_permanent_serialize_hash(&ce->constants_table, script, info, buf, zend_permanent_serialize_zval);
	SERIALIZE_PTR(ZEND_CE_FILENAME(ce));
	SERIALIZE_PTR(ZEND_CE_DOC_COMMENT(ce));
	zend_permanent_serialize_hash(&ce->properties_info, script, info, buf, zend_permanent_serialize_prop_info);

	if (ce->trait_aliases) {
		zend_trait_alias **p, *q;

		SERIALIZE_PTR(ce->trait_aliases);
		p = ce->trait_aliases;
		UNSERIALIZE_PTR(p);

		while (*p) {
			SERIALIZE_PTR(*p);
			q = *p;
			UNSERIALIZE_PTR(q);

			if (q->trait_method) {
				zend_trait_method_reference *m;

				SERIALIZE_PTR(q->trait_method);
				m = q->trait_method;
				UNSERIALIZE_PTR(m);

				if (m->method_name) {
					SERIALIZE_PTR(m->method_name);
				}
				if (m->class_name) {
					SERIALIZE_PTR(m->class_name);
				}
			}

			if (q->alias) {
				SERIALIZE_PTR(q->alias);
			}
			p++;
		}
	}

	if (ce->trait_precedences) {
		zend_trait_precedence **p, *q;

		SERIALIZE_PTR(ce->trait_precedences);
		p = ce->trait_precedences;
		UNSERIALIZE_PTR(p);

		while (*p) {
			SERIALIZE_PTR(*p);
			q = *p;
			UNSERIALIZE_PTR(q);

			if (q->trait_method) {
				zend_trait_method_reference *m;

				SERIALIZE_PTR(q->trait_method);
				m = q->trait_method;
				UNSERIALIZE_PTR(m);

				if (m->method_name) {
					SERIALIZE_PTR(m->method_name);
				}
				if (m->class_name) {
					SERIALIZE_PTR(m->class_name);
				}
			}

			if (q->exclude_from_classes) {
				zend_string **s;

				SERIALIZE_PTR(q->exclude_from_classes);
				s = (zend_string**)q->exclude_from_classes;
				UNSERIALIZE_PTR(s);

				while (*s) {
					SERIALIZE_PTR(*s);
					s++;
				}
			}
			p++;
		}
	}

	SERIALIZE_PTR(ce->parent);
	SERIALIZE_PTR(ce->constructor);
	SERIALIZE_PTR(ce->destructor);
	SERIALIZE_PTR(ce->clone);
	SERIALIZE_PTR(ce->__get);
	SERIALIZE_PTR(ce->__set);
	SERIALIZE_PTR(ce->__call);
	SERIALIZE_PTR(ce->serialize_func);
	SERIALIZE_PTR(ce->unserialize_func);
	SERIALIZE_PTR(ce->__isset);
	SERIALIZE_PTR(ce->__unset);
	SERIALIZE_PTR(ce->__tostring);
	SERIALIZE_PTR(ce->__callstatic);
	SERIALIZE_PTR(ce->__debugInfo);
}

static void zend_permanent_serialize(zend_persistent_script  *script,
                                     zend_permanent_metainfo *info,
                                     void                    *buf)
{
	zend_persistent_script *new_script;

	zend_shared_alloc_clear_xlat_table();

	memcpy(info->magic, "OPCACHE", 8);
	info->mem_size = script->size;
	info->str_size = 0;
	info->script_offset = (char*)script - (char*)script->mem;

	memcpy(buf, script->mem, script->size);

	new_script = (zend_persistent_script*)((char*)buf + info->script_offset);
	SERIALIZE_PTR(new_script->full_path);

	zend_permanent_serialize_hash(&new_script->class_table, script, info, buf, zend_permanent_serialize_class);
	zend_permanent_serialize_hash(&new_script->function_table, script, info, buf, zend_permanent_serialize_func);
	zend_permanent_serialize_op_array(&new_script->main_op_array, script, info, buf);

	SERIALIZE_PTR(new_script->arena_mem);
	new_script->mem = NULL;
}

int zend_permanent_script_store(zend_persistent_script *script)
{
	size_t len;
	int fd;
	char *filename;
	zend_permanent_metainfo info;
	struct iovec vec[3];
	void *mem, *buf;
	zend_string *strings;

	len = strlen(ZCG(accel_directives).permanent_cache);
	filename = emalloc(len + 33 + script->full_path->len + sizeof(SUFFIX));
	memcpy(filename, ZCG(accel_directives).permanent_cache, len);
	filename[len] = '/';
	memcpy(filename + len + 1, ZCG(system_id), 32);
	memcpy(filename + len + 33, script->full_path->val, script->full_path->len);
	memcpy(filename + len + 33 + script->full_path->len, SUFFIX, sizeof(SUFFIX));

	if (zend_permanent_mkdir(filename, len) != SUCCESS) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot create directory for file '%s'\n", filename);
		efree(filename);
		return FAILURE;
	}

	fd = open(filename, O_CREAT | O_EXCL | O_RDWR, S_IRWXU);
	if (fd < 0) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot create file '%s'\n", filename);
		efree(filename);
		return FAILURE;
	}

#ifdef __SSE2__
	/* Align to 64-byte boundary */
	mem = emalloc(script->size + 64);
	buf = (void*)(((zend_uintptr_t)mem + 63L) & ~63L);
#else
	mem = buf = emalloc(script->size);
#endif

	info.u.strings = zend_string_alloc(0, 0);

	zend_permanent_serialize(script, &info, buf);

	vec[0].iov_base = &info;
	vec[0].iov_len = sizeof(info);
	vec[1].iov_base = buf;
	vec[1].iov_len = script->size;
	vec[2].iov_base = info.u.strings->val;
	vec[2].iov_len = info.str_size;

	strings = info.u.strings;
	info.u.strings = NULL;

	info.u.checksum = zend_adler32(ADLER32_INIT, buf, script->size);
	info.u.checksum = zend_adler32(info.u.checksum, (signed char*)strings->val, info.str_size);

	if (writev(fd, vec, 3) != (ssize_t)(sizeof(info) + script->size + info.str_size)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot write to file '%s'\n", filename);
		zend_string_release(strings);
		efree(mem);
		unlink(filename);
		efree(filename);
		return FAILURE;
	}

	zend_string_release(strings);
	efree(mem);
	close(fd);
	efree(filename);

	return SUCCESS;
}

static void zend_permanent_unserialize_hash(HashTable               *ht,
                                            zend_persistent_script  *script,
                                            zend_permanent_metainfo *info,
                                            void                    *buf,
                                            unserialize_callback_t   func)
{
	Bucket *p, *end;

	if (!(ht->u.flags & HASH_FLAG_INITIALIZED)) {
		HT_SET_DATA_ADDR(ht, &uninitialized_bucket);
		return;
	}
	if (IS_UNSERIALIZED(ht->arData)) {
		return;
	}
	UNSERIALIZE_PTR(ht->arData);
	p = ht->arData;
	end = p + ht->nNumUsed;
	while (p < end) {
		if (Z_TYPE(p->val) != IS_UNDEF) {
			UNSERIALIZE_PTR(p->key);
			func(&p->val, script, info, buf);
		}
		p++;
	}
}

static zend_ast *zend_permanent_unserialize_ast(zend_ast                *ast,
                                                zend_persistent_script  *script,
                                                zend_permanent_metainfo *info,
                                                void                    *buf)
{
	uint32_t i;

	UNSERIALIZE_PTR(ast);

	if (ast->kind == ZEND_AST_ZVAL) {
		zend_permanent_unserialize_zval(&((zend_ast_zval*)ast)->val, script, info, buf);
	} else if (zend_ast_is_list(ast)) {
		zend_ast_list *list = zend_ast_get_list(ast);
		for (i = 0; i < list->children; i++) {
			if (list->child[i]) {
				list->child[i] = zend_permanent_unserialize_ast(list->child[i], script, info, buf);
			}
		}
	} else {
		uint32_t children = zend_ast_get_num_children(ast);
		for (i = 0; i < children; i++) {
			if (ast->child[i]) {
				ast->child[i] = zend_permanent_unserialize_ast(ast->child[i], script, info, buf);
			}
		}
	}
	return ast;
}

static void zend_permanent_unserialize_zval(zval                    *zv,
                                            zend_persistent_script  *script,
                                            zend_permanent_metainfo *info,
                                            void                    *buf)
{
	switch (Z_TYPE_P(zv)) {
		case IS_STRING:
		case IS_CONSTANT:
			if (!IS_UNSERIALIZED(Z_STR_P(zv))) {
				UNSERIALIZE_PTR(Z_STR_P(zv));
			}
			break;
		case IS_ARRAY:
			if (!IS_UNSERIALIZED(Z_ARR_P(zv))) {
				HashTable *ht;

				UNSERIALIZE_PTR(Z_ARR_P(zv));
				ht = Z_ARR_P(zv);
				zend_permanent_unserialize_hash(ht, script, info, buf, zend_permanent_unserialize_zval);
			}
			break;
		case IS_REFERENCE:
			if (!IS_UNSERIALIZED(Z_REF_P(zv))) {
				zend_reference *ref;

				UNSERIALIZE_PTR(Z_REF_P(zv));
				ref = Z_REF_P(zv);
				zend_permanent_unserialize_zval(&ref->val, script, info, buf);
			}
			break;
		case IS_CONSTANT_AST:
			if (!IS_UNSERIALIZED(Z_AST_P(zv))) {
				zend_ast_ref *ast;

				UNSERIALIZE_PTR(Z_AST_P(zv));
				ast = Z_AST_P(zv);
				if (!IS_UNSERIALIZED(ast->ast)) {
					ast->ast = zend_permanent_unserialize_ast(ast->ast, script, info, buf);
				}
			}
			break;
	}
}

static void zend_permanent_unserialize_op_array(zend_op_array           *op_array,
                                                zend_persistent_script  *script,
                                                zend_permanent_metainfo *info,
                                                void                    *buf)
{
	if (op_array->static_variables && !IS_UNSERIALIZED(op_array->static_variables)) {
		HashTable *ht;

		UNSERIALIZE_PTR(op_array->static_variables);
		ht = op_array->static_variables;
		zend_permanent_unserialize_hash(ht, script, info, buf, zend_permanent_unserialize_zval);
	}

	if (op_array->literals && !IS_UNSERIALIZED(op_array->literals)) {
		zval *p, *end;

		UNSERIALIZE_PTR(op_array->literals);
		p = op_array->literals;
		end = p + op_array->last_literal;
		while (p < end) {
			zend_permanent_unserialize_zval(p, script, info, buf);
			p++;
		}
	}

	if (!IS_UNSERIALIZED(op_array->opcodes)) {
		zend_op *opline, *end;

		UNSERIALIZE_PTR(op_array->opcodes);
		opline = op_array->opcodes;
		end = opline + op_array->last;
		while (opline < end) {
# if ZEND_USE_ABS_CONST_ADDR
			if (ZEND_OP1_TYPE(opline) == IS_CONST) {
				UNSERIALIZE_PTR(opline->op1.zv);
			}
			if (ZEND_OP2_TYPE(opline) == IS_CONST) {
				UNSERIALIZE_PTR(opline->op2.zv);
			}
# endif
# if ZEND_USE_ABS_JMP_ADDR
			switch (opline->opcode) {
				case ZEND_JMP:
				case ZEND_GOTO:
				case ZEND_FAST_CALL:
					UNSERIALIZE_PTR(opline->op1.jmp_addr);
					break;
				case ZEND_JMPZNZ:
					/* relative extended_value don't have to be changed */
					/* break omitted intentionally */
				case ZEND_JMPZ:
				case ZEND_JMPNZ:
				case ZEND_JMPZ_EX:
				case ZEND_JMPNZ_EX:
				case ZEND_JMP_SET:
				case ZEND_COALESCE:
				case ZEND_NEW:
				case ZEND_FE_RESET_R:
				case ZEND_FE_RESET_RW:
				case ZEND_FE_FETCH_R:
				case ZEND_FE_FETCH_RW:
				case ZEND_ASSERT_CHECK:
					UNSERIALIZE_PTR(opline->op2.jmp_addr);
					break;
			}
# endif
			ZEND_VM_SET_OPCODE_HANDLER(opline);
			opline++;
		}

		if (op_array->arg_info) {
			zend_arg_info *p, *end;
			UNSERIALIZE_PTR(op_array->arg_info);
			p = op_array->arg_info;
			end = p + op_array->num_args;
			if (op_array->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) {
				p--;
			}
			if (op_array->fn_flags & ZEND_ACC_VARIADIC) {
				end++;
			}
			while (p < end) {
				if (!IS_UNSERIALIZED(p->name)) {
					UNSERIALIZE_PTR(p->name);
				}
				if (!IS_UNSERIALIZED(p->class_name)) {
					UNSERIALIZE_PTR(p->class_name);
				}
				p++;
			}
		}

		if (op_array->vars) {
			zend_string **p, **end;

			UNSERIALIZE_PTR(op_array->vars);
			p = op_array->vars;
			end = p + op_array->last_var;
			while (p < end) {
				if (!IS_UNSERIALIZED(*p)) {
					UNSERIALIZE_PTR(*p);
				}
				p++;
			}
		}

		UNSERIALIZE_PTR(op_array->function_name);
		UNSERIALIZE_PTR(op_array->filename);
		UNSERIALIZE_PTR(op_array->brk_cont_array);
		UNSERIALIZE_PTR(op_array->scope);
		UNSERIALIZE_PTR(op_array->doc_comment);
		UNSERIALIZE_PTR(op_array->try_catch_array);
		UNSERIALIZE_PTR(op_array->prototype);
	}
}

static void zend_permanent_unserialize_func(zval                    *zv,
                                            zend_persistent_script  *script,
                                            zend_permanent_metainfo *info,
                                            void                    *buf)
{
	zend_op_array *op_array;

	UNSERIALIZE_PTR(Z_PTR_P(zv));
	op_array = Z_PTR_P(zv);
	zend_permanent_unserialize_op_array(op_array, script, info, buf);
}

static void zend_permanent_unserialize_prop_info(zval                    *zv,
                                                 zend_persistent_script  *script,
                                                 zend_permanent_metainfo *info,
                                                 void                    *buf)
{
	if (!IS_UNSERIALIZED(Z_PTR_P(zv))) {
		zend_property_info *prop;

		UNSERIALIZE_PTR(Z_PTR_P(zv));
		prop = Z_PTR_P(zv);

		if (prop->ce && !IS_UNSERIALIZED(prop->ce)) {
			UNSERIALIZE_PTR(prop->ce);
		}
		if (prop->name && !IS_UNSERIALIZED(prop->name)) {
			UNSERIALIZE_PTR(prop->name);
		}
		if (prop->doc_comment && !IS_UNSERIALIZED(prop->doc_comment)) {
			UNSERIALIZE_PTR(prop->doc_comment);
		}
	}
}

static void zend_permanent_unserialize_class(zval                    *zv,
                                             zend_persistent_script  *script,
                                             zend_permanent_metainfo *info,
                                             void                    *buf)
{
	zend_class_entry *ce;

	UNSERIALIZE_PTR(Z_PTR_P(zv));
	ce = Z_PTR_P(zv);

	UNSERIALIZE_PTR(ce->name);
	zend_permanent_unserialize_hash(&ce->function_table, script, info, buf, zend_permanent_unserialize_func);
	if (ce->default_properties_table) {
		zval *p, *end;

		UNSERIALIZE_PTR(ce->default_properties_table);
		p = ce->default_properties_table;
		end = p + ce->default_properties_count;
		while (p < end) {
			zend_permanent_unserialize_zval(p, script, info, buf);
			p++;
		}
	}
	if (ce->default_static_members_table) {
		zval *p, *end;

		UNSERIALIZE_PTR(ce->default_static_members_table);
		p = ce->default_static_members_table;
		end = p + ce->default_static_members_count;
		while (p < end) {
			zend_permanent_unserialize_zval(p, script, info, buf);
			p++;
		}
	}
	zend_permanent_unserialize_hash(&ce->constants_table, script, info, buf, zend_permanent_unserialize_zval);
	UNSERIALIZE_PTR(ZEND_CE_FILENAME(ce));
	UNSERIALIZE_PTR(ZEND_CE_DOC_COMMENT(ce));
	zend_permanent_unserialize_hash(&ce->properties_info, script, info, buf, zend_permanent_unserialize_prop_info);

	if (ce->trait_aliases) {
		zend_trait_alias **p, *q;

		UNSERIALIZE_PTR(ce->trait_aliases);
		p = ce->trait_aliases;

		while (*p) {
			UNSERIALIZE_PTR(*p);
			q = *p;

			if (q->trait_method) {
				zend_trait_method_reference *m;

				UNSERIALIZE_PTR(q->trait_method);
				m = q->trait_method;

				if (m->method_name) {
					UNSERIALIZE_PTR(m->method_name);
				}
				if (m->class_name) {
					UNSERIALIZE_PTR(m->class_name);
				}
			}

			if (q->alias) {
				UNSERIALIZE_PTR(q->alias);
			}
			p++;
		}
	}

	if (ce->trait_precedences) {
		zend_trait_precedence **p, *q;

		UNSERIALIZE_PTR(ce->trait_precedences);
		p = ce->trait_precedences;

		while (*p) {
			UNSERIALIZE_PTR(*p);
			q = *p;

			if (q->trait_method) {
				zend_trait_method_reference *m;

				UNSERIALIZE_PTR(q->trait_method);
				m = q->trait_method;

				if (m->method_name) {
					UNSERIALIZE_PTR(m->method_name);
				}
				if (m->class_name) {
					UNSERIALIZE_PTR(m->class_name);
				}
			}

			if (q->exclude_from_classes) {
				zend_string **s;

				UNSERIALIZE_PTR(q->exclude_from_classes);
				s = (zend_string**)q->exclude_from_classes;

				while (*s) {
					UNSERIALIZE_PTR(*s);
					s++;
				}
			}
			p++;
		}
	}

	UNSERIALIZE_PTR(ce->parent);
	UNSERIALIZE_PTR(ce->constructor);
	UNSERIALIZE_PTR(ce->destructor);
	UNSERIALIZE_PTR(ce->clone);
	UNSERIALIZE_PTR(ce->__get);
	UNSERIALIZE_PTR(ce->__set);
	UNSERIALIZE_PTR(ce->__call);
	UNSERIALIZE_PTR(ce->serialize_func);
	UNSERIALIZE_PTR(ce->unserialize_func);
	UNSERIALIZE_PTR(ce->__isset);
	UNSERIALIZE_PTR(ce->__unset);
	UNSERIALIZE_PTR(ce->__tostring);
	UNSERIALIZE_PTR(ce->__callstatic);
	UNSERIALIZE_PTR(ce->__debugInfo);
}

static void zend_permanent_unserialize(zend_persistent_script  *script,
                                       zend_permanent_metainfo *info,
                                       void                    *buf)
{
	script->mem = buf;

	UNSERIALIZE_PTR(script->full_path);

	zend_permanent_unserialize_hash(&script->class_table, script, info, buf, zend_permanent_unserialize_class);
	zend_permanent_unserialize_hash(&script->function_table, script, info, buf, zend_permanent_unserialize_func);
	zend_permanent_unserialize_op_array(&script->main_op_array, script, info, buf);

	UNSERIALIZE_PTR(script->arena_mem);
}

zend_persistent_script *zend_permanent_script_load(zend_string *full_path)
{
	size_t len;
	int fd;
	char *filename;
	zend_persistent_script *script;
	zend_permanent_metainfo info;
	zend_accel_hash_entry *bucket;
	void *mem, *buf;

	len = strlen(ZCG(accel_directives).permanent_cache);
	filename = emalloc(len + 33 + full_path->len + sizeof(SUFFIX));
	memcpy(filename, ZCG(accel_directives).permanent_cache, len);
	filename[len] = '/';
	memcpy(filename + len + 1, ZCG(system_id), 32);
	memcpy(filename + len + 33, full_path->val, full_path->len);
	memcpy(filename + len + 33 + full_path->len, SUFFIX, sizeof(SUFFIX));

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		efree(filename);
		return NULL;
	}

	if (read(fd, &info, sizeof(info)) != sizeof(info)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s'\n", filename);
		efree(filename);
		return NULL;
	}

	//TODO: verify info

	mem = emalloc(info.mem_size + info.str_size);

	if (read(fd, mem, info.mem_size + info.str_size) != (ssize_t)(info.mem_size + info.str_size)) {
		zend_accel_error(ACCEL_LOG_WARNING, "opcache cannot read from file '%s'\n", filename);
		close(fd);
		efree(mem);
		efree(filename);
		return NULL;
	}
	close(fd);

	/* verify checksum */
	if (zend_adler32(ADLER32_INIT, mem, info.mem_size + info.str_size) != info.u.checksum) {
		zend_accel_error(ACCEL_LOG_WARNING, "corrupted file '%s'\n", filename);
		unlink(filename);
		efree(mem);
		efree(filename);
		return NULL;
	}

	/* exclusive lock */
	zend_shared_alloc_lock();

	/* Check if we still need to put the file into the cache (may be it was
	 * already stored by another process. This final check is done under
	 * exclusive lock) */
	bucket = zend_accel_hash_find_entry(&ZCSG(hash), full_path);
	if (bucket) {
		script = (zend_persistent_script *)bucket->data;
		if (!script->corrupted) {
			zend_shared_alloc_unlock();
			efree(mem);
			efree(filename);
			return script;
		}
	}

	if (zend_accel_hash_is_full(&ZCSG(hash))) {
		zend_accel_error(ACCEL_LOG_DEBUG, "No more entries in hash table!");
		ZSMMG(memory_exhausted) = 1;
		zend_accel_schedule_restart_if_necessary(ACCEL_RESTART_HASH);
		zend_shared_alloc_unlock();
		efree(mem);
		efree(filename);
		return NULL;
	}

#ifdef __SSE2__
	/* Align to 64-byte boundary */
	buf = zend_shared_alloc(info.mem_size + 64);
	buf = (void*)(((zend_uintptr_t)buf + 63L) & ~63L);
#else
	buf = zend_shared_alloc(info.mem_size);
#endif

	if (!buf) {
		zend_accel_schedule_restart_if_necessary(ACCEL_RESTART_OOM);
		zend_shared_alloc_unlock();
		efree(mem);
		efree(filename);
		return NULL;
	}

	memcpy(buf, mem, info.mem_size);

	info.u.chars = ((char*)mem + info.mem_size);
	script = (zend_persistent_script*)((char*)buf + info.script_offset);
	zend_permanent_unserialize(script, &info, buf);

	script->dynamic_members.checksum = zend_accel_script_checksum(script);

	zend_accel_hash_update(&ZCSG(hash), script->full_path->val, script->full_path->len, 0, script);

	zend_shared_alloc_unlock();
	efree(mem);
	efree(filename);

	return script;
}