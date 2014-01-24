/*
 * Copyright (C) 2014  Tresys Technology, LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sepol/module.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/polcaps.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/util.h>

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

char *progname;
FILE *out_file;

#define STACK_SIZE 16
#define DEFAULT_LEVEL "systemlow"
#define DEFAULT_OBJECT "object_r"

static void log_err(char *fmt, ...)
{
	va_list argptr;
	va_start(argptr, fmt);
	if (vfprintf(stderr, fmt, argptr) < 0) {
		_exit(EXIT_FAILURE);
	}
	va_end(argptr);
	if (fprintf(stderr, "\n") < 0) {
		_exit(EXIT_FAILURE);
	}
}

static void cil_indent(int indent)
{
	if (fprintf(out_file, "%*s", indent * 4, "") < 0) {
		log_err("Failed to write to output");
		_exit(EXIT_FAILURE);
	}
}

static void cil_printf(char *fmt, ...) {
	va_list argptr;
	va_start(argptr, fmt);
	if (vfprintf(out_file, fmt, argptr) < 0) {
		log_err("Failed to write to output");
		_exit(EXIT_FAILURE);
	}
	va_end(argptr);
}

static void cil_println(int indent, char *fmt, ...)
{
	cil_indent(indent);
	va_list argptr;
	va_start(argptr, fmt);
	if (vfprintf(out_file, fmt, argptr) < 0) {
		log_err("Failed to write to output");
		_exit(EXIT_FAILURE);
	}
	va_end(argptr);
	if (fprintf(out_file, "\n") < 0) {
		log_err("Failed to write to output");
		_exit(EXIT_FAILURE);
	}
}

struct map_args {
	struct policydb *pdb;
	struct avrule_block *block;
	struct avrule_decl *decl;
	int scope;
	int indent;
	int sym_index;
};

struct stack {
	 void **stack;
	 int pos;
	 int size;
};

static int stack_destroy(struct stack **stack)
{
	if (stack == NULL || *stack == NULL) {
		return 0;
	}

	free((*stack)->stack);
	free(*stack);
	*stack = NULL;

	return 0;
}

static int stack_init(struct stack **stack)
{
	int rc = -1;
	struct stack *s = calloc(1, sizeof(*s));
	if (s == NULL) {
		goto exit;
	}

	s->stack = malloc(sizeof(*s->stack) * STACK_SIZE);
	if (s->stack == NULL) {
		goto exit;
	}

	s->pos = -1;
	s->size = STACK_SIZE;

	*stack = s;

	return 0;

exit:
	stack_destroy(&s);
	return rc;
}

static int stack_push(struct stack *stack, void *ptr)
{
	int rc = -1;
	void *new_stack;

	if (stack->pos + 1 == stack->size) {
		new_stack = realloc(stack->stack, sizeof(*stack->stack) * (stack->size * 2));
		if (new_stack == NULL) {
			goto exit;
		}
		stack->stack = new_stack;
		stack->size *= 2;
	}

	stack->pos++;
	stack->stack[stack->pos] = ptr;

	rc = 0;
exit:
	return rc;
}

static void *stack_pop(struct stack *stack)
{
	if (stack->pos == -1) {
		return NULL;
	}

	stack->pos--;
	return stack->stack[stack->pos + 1];
}

static void *stack_peek(struct stack *stack)
{
	if (stack->pos == -1) {
		return NULL;
	}

	return stack->stack[stack->pos];
}


static int semantic_level_to_cil(struct policydb *pdb, int sens_offset, struct mls_semantic_level *level)
{
	struct mls_semantic_cat *cat;

	cil_printf("(%s ", pdb->p_sens_val_to_name[level->sens - sens_offset]);

	if (level->cat != NULL) {
		cil_printf("(");
	}

	for (cat = level->cat; cat != NULL; cat = cat->next) {
		if (cat->low == cat->high) {
			cil_printf("%s", pdb->p_cat_val_to_name[cat->low - 1]);
		} else {
			cil_printf("range %s %s", pdb->p_cat_val_to_name[cat->low - 1], pdb->p_cat_val_to_name[cat->high - 1]);
		}

		if (cat->next != NULL) {
			cil_printf(" ");
		}
	}

	if (level->cat != NULL) {
		cil_printf(")");
	}

	cil_printf(")");

	return 0;
}

static int avrule_to_cil(int indent, struct policydb *pdb, uint32_t type, char *src, char *tgt, struct class_perm_node *classperms)
{
	int rc = -1;
	char *rule;
	struct class_perm_node *classperm;
	char *perms;

	switch (type) {
	case AVRULE_ALLOWED:
		rule = "allow";
		break;
	case AVRULE_AUDITALLOW:
		rule = "auditallow";
		break;
	case AVRULE_AUDITDENY:
		rule = "auditdenty";
		break;
	case AVRULE_DONTAUDIT:
		rule = "dontaudit";
		break;
	case AVRULE_NEVERALLOW:
		rule = "neverallow";
		break;
	case AVRULE_TRANSITION:
		rule = "typetransition";
		break;
	case AVRULE_MEMBER:
		rule = "typemember";
		break;
	case AVRULE_CHANGE:
		rule = "typechange";
		break;
	default:
		log_err("Unknown avrule type: %i", type);
		rc = -1;
		goto exit;
	}

	for (classperm = classperms; classperm != NULL; classperm = classperm->next) {
		if (type & AVRULE_AV) {
			perms = sepol_av_to_string(pdb, classperm->class, classperm->data);
			if (perms == NULL) {
				log_err("Failed to generate permission string");
				rc = -1;
				goto exit;
			}
			cil_println(indent, "(%s %s %s (%s (%s)))",
					rule, src, tgt,
					pdb->p_class_val_to_name[classperm->class - 1],
					perms + 1);
		} else {
			cil_println(indent, "(%s %s %s %s %s)",
					rule, src, tgt,
					pdb->p_class_val_to_name[classperm->class - 1],
					pdb->p_type_val_to_name[classperm->data - 1]);
		}
	}

	return 0;

exit:
	return rc;
}

static int num_digits(int n)
{
	int num = 1;
	while (n >= 10) {
		n /= 10;
		num++;
	}
	return num;
}

static int set_to_cil_attr(int indent, struct policydb *pdb, int is_type, struct ebitmap *pos, struct ebitmap *neg, uint32_t flags, char ***names, uint32_t *num_names)
{
	// CIL doesn't support anonymous positive/negative/complemented sets.  So
	// instead we create a CIL type/roleattributeset that matches the set. If
	// the set has a negative set, then convert it to is (P & !N), where P is
	// the list of members in the positive set , and N is the list of members
	// in the negative set. Additonally, if the set is complemented, then wrap
	// the whole thing with a negation.

	static unsigned int num_attrs = 0;

	int rc = -1;
	struct ebitmap_node *node;
	unsigned int i;
	char *attr_infix;
	char *statement;
	char *attr;
	int len;
	int rlen;
	int has_positive = pos && (ebitmap_cardinality(pos) > 0);
	int has_negative = neg && (ebitmap_cardinality(neg) > 0);
	char **val_to_name;

	num_attrs++;

	if (is_type) {
		attr_infix = "_typeattr_";
		statement = "type";
		val_to_name = pdb->p_type_val_to_name;
	} else {
		attr_infix = "_roleattr_";
		statement = "role";
		val_to_name = pdb->p_role_val_to_name;
	}

	len = strlen(pdb->name) + strlen(attr_infix) + num_digits(num_attrs) + 1;
	attr = malloc(len);
	if (attr == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}
	rlen = snprintf(attr, len, "%s%s%i", pdb->name, attr_infix, num_attrs);
	if (rlen < 0 || rlen >= len) {
		log_err("Failed to generate attribute name");
		rc = -1;
		goto exit;
	}

	cil_println(indent, "(%sattribute %s)", statement, attr);
	cil_indent(indent);
	cil_printf("(%sattributeset %s ", statement, attr);

	if (flags & TYPE_STAR) {
		cil_printf("(all)");
	}

	if (flags & TYPE_COMP) {
		cil_printf("(not ");
	}

	if (has_positive && has_negative) {
		cil_printf("(and ");
	}

	if (has_positive) {
		cil_printf("(");
		ebitmap_for_each_bit(pos, node, i) {
			if (!ebitmap_get_bit(pos, i)) {
				continue;
			}
			cil_printf("%s ", val_to_name[i]);
		}
		cil_printf(") ");
	}

	if (has_negative) {
		cil_printf("(not (");

		ebitmap_for_each_bit(neg, node, i) {
			if (!ebitmap_get_bit(neg, i)) {
				continue;
			}
			cil_printf("%s ", val_to_name[i]);
		}

		cil_printf("))");
	}

	if (has_positive && has_negative) {
		cil_printf(")");
	}

	if (flags & TYPE_COMP) {
		cil_printf(")");
	}

	cil_printf(")\n");

	*names = malloc(sizeof(**names));
	if (*names == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}
	*names[0] = attr;
	*num_names = 1;

	return 0;
exit:
	return rc;
}

static int ebitmap_to_cil(struct policydb *pdb, struct ebitmap *map, int type)
{
	struct ebitmap_node *node;
	uint32_t i;
	char **val_to_name = pdb->sym_val_to_name[type];

	ebitmap_for_each_bit(map, node, i) {
		if (!ebitmap_get_bit(map, i)) {
			continue;
		}
		cil_printf("%s ", val_to_name[i]);
	}

	return 0;
}

static int ebitmap_to_names(char** vals_to_names, struct ebitmap map, char ***names, uint32_t *num_names)
{
	int rc = -1;
	struct ebitmap_node *node;
	uint32_t i;
	uint32_t num = 0;
	uint32_t max = 8;
	char **name_arr = NULL;

	name_arr = malloc(sizeof(*name_arr) * max);
	if (name_arr == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}

	ebitmap_for_each_bit(&map, node, i) {
		if (!ebitmap_get_bit(&map, i)) {
			continue;
		}

		if (num + 1 == max) {
			max *= 2;
			name_arr = realloc(name_arr, sizeof(*name_arr) * max);
			if (name_arr == NULL) {
				log_err("Out of memory");
				rc = -1;
				goto exit;
			}
		}

		name_arr[num] = strdup(vals_to_names[i]);
		if (name_arr[num] == NULL) {
			log_err("Out of memory");
			rc = -1;
			goto exit;
		}
		num++;
	}

	*names = name_arr;
	*num_names = num;

	return 0;

exit:
	for (i = 0; i < num; i++) {
		free(name_arr[i]);
	}
	free(name_arr);
	return rc;
}

static int typeset_to_names(int indent, struct policydb *pdb, struct type_set *ts, char ***names, uint32_t *num_names)
{
	int rc = -1;
	if (ebitmap_cardinality(&ts->negset) > 0 || ts->flags != 0) {
		rc = set_to_cil_attr(indent, pdb, 1, &ts->types, &ts->negset, ts->flags, names, num_names);
		if (rc != 0) {
			goto exit;
		}
	} else {
		rc = ebitmap_to_names(pdb->p_type_val_to_name, ts->types, names, num_names);
		if (rc != 0) {
			goto exit;
		}
	}

	return 0;
exit:
	return rc;
}

static int roleset_to_names(int indent, struct policydb *pdb, struct role_set *rs, char ***names, uint32_t *num_names)
{
	int rc = -1;
	if (rs->flags != 0) {
		rc = set_to_cil_attr(indent, pdb, 0, &rs->roles, NULL, rs->flags, names, num_names);
		if (rc != 0) {
			goto exit;
		}
	} else {
		rc = ebitmap_to_names(pdb->p_role_val_to_name, rs->roles, names, num_names);
		if (rc != 0) {
			goto exit;
		}
	}

	return 0;
exit:
	return rc;
}

static void names_destroy(char ***names, uint32_t *num_names)
{
	char **arr = *names;
	uint32_t num = *num_names;
	uint32_t i;

	for (i = 0; i < num; i++) {
		free(arr[i]);
		arr[i] = NULL;
	}
	free(arr);

	*names = NULL;
	*num_names = 0;
}


static int name_list_to_string(char **names, int num_names, char **string)
{
	// create a space separated string of the names
	int rc = -1;
	int len = 0;
	int i;
	char *str;
	char *strpos;
	int name_len;
	int rlen;

	for (i = 0; i < num_names; i++) {
		len += strlen(names[i]);
	}

	// add spaces + null terminator
	len += (num_names - 1) + 1;

	str = malloc(len);
	if (str == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}

	strpos = str;

	for (i = 0; i < num_names; i++) {
		name_len = strlen(names[i]);
		rlen = snprintf(strpos, len - (strpos - str), "%s", names[i]);
		if (rlen < 0 || rlen >= len) {
			log_err("Failed to generate name list");
			rc = -1;
			goto exit;
		}

		if (i < num_names - 1) {
			strpos[name_len] = ' ';
		}
		strpos += name_len + 1;
	}

	*string = str;

	return 0;
exit:
	return rc;
}

static int avrule_list_to_cil(int indent, struct policydb *pdb, struct avrule *avrule_list)
{
	int rc = -1;
	struct avrule *avrule;
	char **snames = NULL;
	char **tnames = NULL;
	uint32_t num_snames;
	uint32_t num_tnames;
	uint32_t s;
	uint32_t t;

	for (avrule = avrule_list; avrule != NULL; avrule = avrule->next) {

		rc = typeset_to_names(indent, pdb, &avrule->stypes, &snames, &num_snames);
		if (rc != 0) {
			goto exit;
		}

		rc = typeset_to_names(indent, pdb, &avrule->ttypes, &tnames, &num_tnames);
		if (rc != 0) {
			goto exit;
		}

		for (s = 0; s < num_snames; s++) {
			for (t = 0; t < num_tnames; t++) {
				rc = avrule_to_cil(indent, pdb, avrule->specified, snames[s], tnames[t], avrule->perms);
				if (rc != 0) {
					goto exit;
				}
			}

			if (avrule->flags & RULE_SELF) {
				rc = avrule_to_cil(indent, pdb, avrule->specified, snames[s], "self", avrule->perms);
				if (rc != 0) {
					goto exit;
				}
			}
		}

		names_destroy(&snames, &num_snames);
		names_destroy(&tnames, &num_tnames);
	}

	return 0;

exit:
	names_destroy(&snames, &num_snames);
	names_destroy(&tnames, &num_tnames);

	return rc;
}

static int cond_expr_to_cil(int indent, struct policydb *pdb, struct cond_expr *cond_expr, uint32_t flags)
{
	int rc = -1;
	struct cond_expr *curr;
	struct stack *stack = NULL;
	int len = 0;
	int rlen;
	char *new_val = NULL;
	char *val1 = NULL;
	char *val2 = NULL;
	int num_params;
	char *op;
	char *fmt_str;
	char *type;

	rc = stack_init(&stack);
	if (rc != 0) {
		log_err("Out of memory");
		goto exit;
	}

	for (curr = cond_expr; curr != NULL; curr = curr->next) {
		if (curr->expr_type == COND_BOOL) {
			val1 = pdb->p_bool_val_to_name[curr->bool - 1];
			// length of boolean + 2 parens + null terminator
			len = strlen(val1) + 2 + 1;
			new_val = malloc(len);
			if (new_val == NULL) {
				log_err("Out of memory");
				rc = -1;
				goto exit;
			}
			rlen = snprintf(new_val, len, "(%s)", val1);
			if (rlen < 0 || rlen >= len) {
				log_err("Failed to generate conditional expression");
				rc = -1;
				goto exit;
			}
			num_params = 0;
		} else {
			switch(curr->expr_type) {
			case COND_NOT:	op = "not";	break;
			case COND_OR:	op = "or";	break;
			case COND_AND:	op = "and";	break;
			case COND_XOR:	op = "xor";	break;
			case COND_EQ:	op = "eq";	break;
			case COND_NEQ:	op = "neq";	break;
			default:
				rc = -1;
				goto exit;
			}

			num_params = curr->expr_type == COND_NOT ? 1 : 2;

			if (num_params == 1) {
				val1 = stack_pop(stack);
				val2 = strdup("");
				if (val2 == NULL) {
					log_err("Out of memory");
					rc = -1;
					goto exit;
				}
				fmt_str = "(%s %s)";
			} else {
				val2 = stack_pop(stack);
				val1 = stack_pop(stack);
				fmt_str = "(%s %s %s)";
			}

			if (val1 == NULL || val2 == NULL) {
				log_err("Invalid conditional expression");
				rc = -1;
				goto exit;
			}

			// length = length of parameters +
			//          length of operator +
			//          1 space preceeding each parameter +
			//          2 parens around the whole expression
			//          + null terminator
			len = strlen(val1) + strlen(val2) + strlen(op) + (num_params * 1) + 2 + 1;
			new_val = malloc(len);
			if (new_val == NULL) {
				log_err("Out of memory");
				rc = -1;
				goto exit;
			}

			// although we always supply val2 and there isn't always a 2nd
			// value, it should only be used when there are actually two values
			// in the format strings
			rlen = snprintf(new_val, len, fmt_str, op, val1, val2);
			if (rlen < 0 || rlen >= len) {
				log_err("Failed to generate conditional expression");
				rc = -1;
				goto exit;
			}

			free(val1);
			free(val2);
			val1 = NULL;
			val2 = NULL;
		}

		rc = stack_push(stack, new_val);
		if (rc != 0) {
			log_err("Out of memory");
			goto exit;
		}
		new_val = NULL;
	}

	if (flags & COND_NODE_FLAGS_TUNABLE) {
		type = "tunableif";
	} else {
		type = "booleanif";
	}

	val1 = stack_pop(stack);
	if (val1 == NULL || stack_peek(stack) != NULL) {
		log_err("Invalid conditional expression");
		rc = -1;
		goto exit;
	}

	cil_println(indent, "(%s %s", type, val1);
	free(val1);
	val1 = NULL;

	rc = 0;

exit:
	free(new_val);
	free(val1);
	free(val2);
	while ((val1 = stack_pop(stack)) != NULL) {
		free(val1);
	}
	stack_destroy(&stack);

	return rc;
}

static int cond_list_to_cil(int indent, struct policydb *pdb, struct cond_node *cond_list)
{
	int rc = -1;
	struct cond_node *cond;

	for (cond = cond_list; cond != NULL; cond = cond->next) {

		rc = cond_expr_to_cil(indent, pdb, cond->expr, cond->flags);
		if (rc != 0) {
			goto exit;
		}

		if (cond->avtrue_list != NULL) {
			cil_println(indent + 1, "(true");
			rc = avrule_list_to_cil(indent + 2, pdb, cond->avtrue_list);
			if (rc != 0) {
				goto exit;
			}
			cil_println(indent + 1, ")");
		}

		if (cond->avfalse_list != NULL) {
			cil_println(indent + 1, "(false");
			rc = avrule_list_to_cil(indent + 2, pdb, cond->avfalse_list);
			if (rc != 0) {
				goto exit;
			}
			cil_println(indent + 1, ")");
		}

		cil_println(indent, ")");
	}

	return 0;

exit:
	return rc;
}

static int role_trans_to_cil(int indent, struct policydb *pdb, struct role_trans_rule *rules)
{
	int rc = -1;
	struct role_trans_rule *rule;
	char **role_names = NULL;
	uint32_t num_role_names = 0;
	char **type_names = NULL;
	uint32_t num_type_names = 0;
	uint32_t type;
	uint32_t role;
	uint32_t i;
	struct ebitmap_node *node;


	for (rule = rules; rule != NULL; rule = rule->next) {
		rc = roleset_to_names(indent, pdb, &rule->roles, &role_names, &num_role_names);
		if (rc != 0) {
			goto exit;
		}

		rc = typeset_to_names(indent, pdb, &rule->types, &type_names, &num_type_names);
		if (rc != 0) {
			goto exit;
		}

		for (role = 0; role < num_role_names; role++) {
			for (type = 0; type < num_type_names; type++) {
				ebitmap_for_each_bit(&rule->classes, node, i) {
					if (!ebitmap_get_bit(&rule->classes, i)) {
						continue;
					}
					cil_println(indent, "(roletransition %s %s %s %s)", role_names[role],
					                                                    type_names[type],
					                                                    pdb->p_class_val_to_name[i],
					                                                    pdb->p_role_val_to_name[rule->new_role - 1]);
				}
			}
		}

		names_destroy(&role_names, &num_role_names);
		names_destroy(&type_names, &num_type_names);
	}

	rc = 0;

exit:
	names_destroy(&role_names, &num_role_names);
	names_destroy(&type_names, &num_type_names);

	return rc;
}

static int role_allows_to_cil(int indent, struct policydb *pdb, struct role_allow_rule *rules)
{
	int rc = -1;
	struct role_allow_rule *rule;
	char **roles = NULL;
	uint32_t num_roles = 0;
	char **new_roles = NULL;
	uint32_t num_new_roles = 0;
	uint32_t i;
	uint32_t j;

	for (rule = rules; rule != NULL; rule = rule->next) {
		rc = roleset_to_names(indent, pdb, &rule->roles, &roles, &num_roles);
		if (rc != 0) {
			goto exit;
		}

		rc = roleset_to_names(indent, pdb, &rule->new_roles, &new_roles, &num_new_roles);
		if (rc != 0) {
			goto exit;
		}

		for (i = 0; i < num_roles; i++) {
			for (j = 0; j < num_new_roles; j++) {
				cil_println(indent, "(roleallow %s %s)", roles[i], new_roles[j]);
			}
		}

		names_destroy(&roles, &num_roles);
		names_destroy(&new_roles, &num_new_roles);
	}

	rc = 0;

exit:
	names_destroy(&roles, &num_roles);
	names_destroy(&new_roles, &num_new_roles);

	return rc;
}

static int range_trans_to_cil(int indent, struct policydb *pdb, struct range_trans_rule *rules)
{
	int rc = -1;
	struct range_trans_rule *rule;
	char **stypes = NULL;
	uint32_t num_stypes = 0;
	char **ttypes = NULL;
	uint32_t num_ttypes = 0;
	struct ebitmap_node *node;
	uint32_t i;
	uint32_t stype;
	uint32_t ttype;

	if (!pdb->mls) {
		return 0;
	}

	for (rule = rules; rule != NULL; rule = rule->next) {
		rc = typeset_to_names(indent, pdb, &rule->stypes, &stypes, &num_stypes);
		if (rc != 0) {
			goto exit;
		}

		rc = typeset_to_names(indent, pdb, &rule->ttypes, &ttypes, &num_ttypes);
		if (rc != 0) {
			goto exit;
		}

		for (stype = 0; stype < num_stypes; stype++) {
			for (ttype = 0; ttype < num_ttypes; ttype++) {
				ebitmap_for_each_bit(&rule->tclasses, node, i) {
					if (!ebitmap_get_bit(&rule->tclasses, i)) {
						continue;
					}

					cil_indent(indent);
					cil_printf("(rangetransition %s %s %s ", stypes[stype], ttypes[ttype], pdb->p_class_val_to_name[i]);

					cil_printf("(");

					rc = semantic_level_to_cil(pdb, 1, &rule->trange.level[0]);
					if (rc != 0) {
						goto exit;
					}

					cil_printf(" ");

					rc = semantic_level_to_cil(pdb, 1, &rule->trange.level[1]);
					if (rc != 0) {
						goto exit;
					}

					cil_printf("))\n");
				}

			}
		}

		names_destroy(&stypes, &num_stypes);
		names_destroy(&ttypes, &num_ttypes);
	}

	rc = 0;

exit:
	names_destroy(&stypes, &num_stypes);
	names_destroy(&ttypes, &num_ttypes);

	return rc;
}

static int filename_trans_to_cil(int indent, struct policydb *pdb, struct filename_trans_rule *rules)
{
	int rc = -1;
	char **stypes = NULL;
	uint32_t num_stypes = 0;
	char **ttypes = NULL;
	uint32_t num_ttypes = 0;
	uint32_t stype;
	uint32_t ttype;

	struct filename_trans_rule *rule;

	for (rule = rules; rule != NULL; rule = rule->next) {
		rc = typeset_to_names(indent, pdb, &rule->stypes, &stypes, &num_stypes);
		if (rc != 0) {
			goto exit;
		}

		rc = typeset_to_names(indent, pdb, &rule->ttypes, &ttypes, &num_ttypes);
		if (rc != 0) {
			goto exit;
		}

		for (stype = 0; stype < num_stypes; stype++) {
			for (ttype = 0; ttype < num_ttypes; ttype++) {
				cil_println(indent, "(typetransition %s %s %s %s %s)", stypes[stype],
				                                                       ttypes[ttype],
				                                                       pdb->p_class_val_to_name[rule->tclass - 1],
				                                                       rule->name,
				                                                       pdb->p_type_val_to_name[rule->otype - 1]);
			}
		}

		names_destroy(&stypes, &num_stypes);
		names_destroy(&ttypes, &num_ttypes);
	}

	rc = 0;
exit:
	names_destroy(&stypes, &num_stypes);
	names_destroy(&ttypes, &num_ttypes);

	return rc;
}


static int class_perm_to_cil(char *key, void *UNUSED(data), void *UNUSED(args))
{
	cil_printf("%s ", key);
	return 0;
}

static int common_to_cil(char *key, void *data, void *UNUSED(arg))
{
	int rc = -1;
	struct common_datum *common = data;

	cil_printf("(common %s (", key);
	rc = hashtab_map(common->permissions.table, class_perm_to_cil, NULL);
	if (rc != 0) {
		goto exit;
	}
	cil_printf("))\n");

	return 0;

exit:
	return rc;
}


static int constraint_expr_to_string(int indent, struct policydb *pdb, struct constraint_expr *exprs, char **expr_string)
{
	int rc = -1;
	struct constraint_expr *expr;
	struct stack *stack = NULL;
	int len = 0;
	int rlen;
	char *new_val = NULL;
	char *val1 = NULL;
	char *val2 = NULL;
	uint32_t num_params;
	char *op;
	char *fmt_str;
	char *attr1;
	char *attr2;
	char *names;
	char **name_list = NULL;
	uint32_t num_names = 0;

	rc = stack_init(&stack);
	if (rc != 0) {
		goto exit;
	}

	for (expr = exprs; expr != NULL; expr = expr->next) {
		if (expr->expr_type == CEXPR_ATTR || expr->expr_type == CEXPR_NAMES) {
			switch (expr->op) {
			case CEXPR_EQ:      op = "eq";     break;
			case CEXPR_NEQ:     op = "neq";    break;
			case CEXPR_DOM:     op = "dom";    break;
			case CEXPR_DOMBY:   op = "domby";  break;
			case CEXPR_INCOMP:  op = "incomp"; break;
			default:
				log_err("Unknown constraint operator type: %i", expr->op);
				rc = -1;
				goto exit;
			}

			switch (expr->attr) {
			case CEXPR_USER:                 attr1 = "u1"; attr2 = "u2"; break;
			case CEXPR_USER | CEXPR_TARGET:  attr1 = "u2"; attr2 = "";   break;
			case CEXPR_USER | CEXPR_XTARGET: attr1 = "u3"; attr2 = "";   break;
			case CEXPR_ROLE:                 attr1 = "r1"; attr2 = "r2"; break;
			case CEXPR_ROLE | CEXPR_TARGET:  attr1 = "r2"; attr2 = "";   break;
			case CEXPR_ROLE | CEXPR_XTARGET: attr1 = "r3"; attr2 = "";   break;
			case CEXPR_TYPE:                 attr1 = "t1"; attr2 = "";   break;
			case CEXPR_TYPE | CEXPR_TARGET:  attr1 = "t2"; attr2 = "";   break;
			case CEXPR_TYPE | CEXPR_XTARGET: attr1 = "t3"; attr2 = "";   break;
			case CEXPR_L1L2:                 attr1 = "l1"; attr2 = "l2"; break;
			case CEXPR_L1H2:                 attr1 = "l1"; attr2 = "h2"; break;
			case CEXPR_H1L2:                 attr1 = "h1"; attr2 = "l2"; break;
			case CEXPR_H1H2:                 attr1 = "h1"; attr2 = "h2"; break;
			case CEXPR_L1H1:                 attr1 = "l1"; attr2 = "h1"; break;
			case CEXPR_L2H2:                 attr1 = "l2"; attr2 = "h2"; break;
			default:
				log_err("Unknown expression attribute type: %i", expr->attr);
				rc = -1;
				goto exit;
			}

			if (expr->expr_type == CEXPR_ATTR) {
				// length of values/attrs + 2 separating spaces + 2 parens + null terminator
				len = strlen(op) + strlen(attr1) + strlen(attr2) + 2 + 2 + 1;
				new_val = malloc(len);
				if (new_val == NULL) {
					log_err("Out of memory");
					rc = -1;
					goto exit;
				}
				rlen = snprintf(new_val, len, "(%s %s %s)", op, attr1, attr2);
				if (rlen < 0 || rlen >= len) {
					log_err("Failed to generate constraint expression");
					rc = -1;
					goto exit;
				}
			} else {
				if (expr->attr & CEXPR_TYPE) {
					rc = typeset_to_names(indent, pdb, expr->type_names, &name_list, &num_names);
					if (rc != 0) {
						goto exit;
					}
				} else if (expr->attr & CEXPR_USER) {
					rc = ebitmap_to_names(pdb->p_user_val_to_name, expr->names, &name_list, &num_names);
					if (rc != 0) {
						goto exit;
					}
				} else if (expr->attr & CEXPR_ROLE) {
					rc = ebitmap_to_names(pdb->p_role_val_to_name, expr->names, &name_list, &num_names);
					if (rc != 0) {
						goto exit;
					}
				}
				rc = name_list_to_string(name_list, num_names, &names);
				if (rc != 0) {
					goto exit;
				}

				// length of values/oper + 2 spaces + 2 parens + null terminator
				len = strlen(op) + strlen(attr1) +  strlen(names) + 2 + 2 + 1;
				new_val = malloc(len);
				if (new_val == NULL) {
					log_err("Out of memory");
					rc = -1;
					goto exit;
				}
				rlen = snprintf(new_val, len, "(%s %s %s)", op, attr1, names);
				if (rlen < 0 || rlen >= len) {
					log_err("Failed to generate constraint expression");
					rc = -1;
					goto exit;
				}

				names_destroy(&name_list, &num_names);
				free(names);
			}

			num_params = 0;
		} else {
			switch (expr->expr_type) {
			case CEXPR_NOT: op = "not"; break;
			case CEXPR_AND: op = "and"; break;
			case CEXPR_OR:  op = "or"; break;
			default:
				log_err("Unknown constraint expression type: %i", expr->expr_type);
				rc = -1;
				goto exit;
			}

			num_params = expr->expr_type == CEXPR_NOT ? 1 : 2;

			if (num_params == 1) {
				val1 = stack_pop(stack);
				val2 = strdup("");
				if (val2 == NULL) {
					log_err("Out of memory");
					rc = -1;
					goto exit;
				}
				fmt_str = "(%s %s)";
			} else {
				val2 = stack_pop(stack);
				val1 = stack_pop(stack);
				fmt_str = "(%s %s %s)";
			}

			if (val1 == NULL || val2 == NULL) {
				log_err("Invalid constraint expression");
				rc = -1;
				goto exit;
			}

			// length = length of parameters +
			//          length of operator +
			//          1 space preceeding each parameter +
			//          2 parens around the whole expression
			//          + null terminator
			len = strlen(val1) + strlen(val2) + strlen(op) + (num_params * 1) + 2 + 1;
			new_val = malloc(len);
			if (new_val == NULL) {
				log_err("Out of memory");
				rc = -1;
				goto exit;
			}

			// although we always supply val2 and there isn't always a 2nd
			// value, it should only be used when there are actually two values
			// in the format strings
			rlen = snprintf(new_val, len, fmt_str, op, val1, val2);
			if (rlen < 0 || rlen >= len) {
				log_err("Failed to generate constraint expression");
				rc = -1;
				goto exit;
			}

			free(val1);
			free(val2);
			val1 = NULL;
			val2 = NULL;
		}

		rc = stack_push(stack, new_val);
		if (rc != 0) {
			log_err("Out of memory");
			goto exit;
		}

		new_val = NULL;
	}

	new_val = stack_pop(stack);
	if (new_val == NULL || stack_peek(stack) != NULL) {
		log_err("Invalid constraint expression");
		rc = -1;
		goto exit;
	}

	*expr_string = new_val;
	new_val = NULL;

	rc = 0;

exit:
	names_destroy(&name_list, &num_names);

	free(new_val);
	free(val1);
	free(val2);
	while ((val1 = stack_pop(stack)) != NULL) {
		free(val1);
	}
	stack_destroy(&stack);

	return rc;
}


static int constraints_to_cil(int indent, struct policydb *pdb, char *classkey, struct class_datum *class, struct constraint_node *constraints, int is_constraint)
{
	int rc = -1;
	struct constraint_node *node;
	char *expr = NULL;
	char *mls;
	char *perms;

	mls = pdb->mls ? "mls" : "";

	for (node = constraints; node != NULL; node = node->next) {

		rc = constraint_expr_to_string(indent, pdb, node->expr, &expr);
		if (rc != 0) {
			goto exit;
		}

		if (is_constraint) {
			perms = sepol_av_to_string(pdb, class->s.value, node->permissions);
			cil_println(indent, "(%sconstrain (%s (%s)) %s)", mls, classkey, perms + 1, expr);
		} else {
			cil_println(indent, "(%svalidatetrans %s %s)", mls, classkey, expr);
		}

		free(expr);
		expr = NULL;
	}

	rc = 0;

exit:
	free(expr);
	return rc;
}

static int class_to_cil(int indent, struct policydb *pdb, struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum, int scope)
{
	int rc = -1;
	struct class_datum *class = datum;
	char *dflt;

	if (scope == SCOPE_REQ) {
		return 0;
	}

	cil_indent(indent);
	cil_printf("(class %s (", key);
	rc = hashtab_map(class->permissions.table, class_perm_to_cil, NULL);
	if (rc != 0) {
		goto exit;
	}
	cil_printf("))\n");

	if (class->comkey != NULL) {
		cil_println(indent, "(classcommon %s %s)", key, class->comkey);
	}

	if (class->default_user != 0) {
		switch (class->default_user) {
		case DEFAULT_SOURCE:	dflt = "source";	break;
		case DEFAULT_TARGET:	dflt = "target";	break;
		default:
			log_err("Unknown default user value: %i", class->default_user);
			rc = -1;
			goto exit;
		}
		cil_println(indent, "(defaultuser %s %s)", key, dflt);
	}

	if (class->default_role != 0) {
		switch (class->default_role) {
		case DEFAULT_SOURCE:	dflt = "source";	break;
		case DEFAULT_TARGET:	dflt = "target";	break;
		default:
			log_err("Unknown default role value: %i", class->default_role);
			rc = -1;
			goto exit;
		}
		cil_println(indent, "(defaultrole %s %s)", key, dflt);
	}

	if (class->default_type != 0) {
		switch (class->default_type) {
		case DEFAULT_SOURCE:	dflt = "source";	break;
		case DEFAULT_TARGET:	dflt = "target";	break;
		default:
			log_err("Unknown default type value: %i", class->default_type);
			rc = -1;
			goto exit;
		}
		cil_println(indent, "(defaulttype %s %s)", key, dflt);
	}

	if (class->default_range != 0) {
		switch (class->default_range) {
		case DEFAULT_SOURCE_LOW:		dflt = "source low";	break;
		case DEFAULT_SOURCE_HIGH:		dflt = "source high";	break;
		case DEFAULT_SOURCE_LOW_HIGH:	dflt = "source low-high";	break;
		case DEFAULT_TARGET_LOW:		dflt = "target low";	break;
		case DEFAULT_TARGET_HIGH:		dflt = "target high";	break;
		case DEFAULT_TARGET_LOW_HIGH:	dflt = "target low-high";	break;
		default:
			log_err("Unknown default range value: %i", class->default_range);
			rc = -1;
			goto exit;
		}
		cil_println(indent, "(defaultrange %s %s)", key, dflt);

	}

	if (class->constraints != NULL) {
		rc = constraints_to_cil(indent, pdb, key, class, class->constraints, 1);
		if (rc != 0) {
			goto exit;
		}
	}

	if (class->validatetrans != NULL) {
		rc = constraints_to_cil(indent, pdb, key, class, class->validatetrans, 0);
		if (rc != 0) {
			goto exit;
		}
	}

	return 0;
exit:
	return rc;
}

static int role_to_cil(int indent, struct policydb *pdb, struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum, int scope)
{
	int rc = -1;
	struct ebitmap_node *node;
	uint32_t i;
	char **types = NULL;
	uint32_t num_types = 0;
	struct role_datum *role = datum;

	switch (role->flavor) {
	case ROLE_ROLE:
		if (scope == SCOPE_DECL) {
			if (pdb->policy_type == SEPOL_POLICY_MOD) {
				// roles are defined twice, once in a module and once in base.
				// CIL doesn't allow duplicate declarations, so only take the
				// roles defined in the modules
				cil_println(indent, "(role %s)", key);

				// the attributes of a decl role are handled elswhere
				rc = 0;
				goto exit;
			}
		}

		if (ebitmap_cardinality(&role->dominates) > 1) {
			log_err("Warning: role 'dominance' statment unsupported in CIL. Dropping from output.");
		}

		rc = typeset_to_names(indent, pdb, &role->types, &types, &num_types);
		if (rc != 0) {
			goto exit;
		}

		for (i = 0; i < num_types; i++) {
			cil_println(indent, "(roletype %s %s)", key, types[i]);
		}

		if (role->bounds > 0) {
			cil_println(indent, "(rolebounds %s %s)", key, pdb->p_role_val_to_name[role->bounds - 1]);
		}
		break;

	case ROLE_ATTRIB:
		if (scope == SCOPE_DECL) {
			cil_println(indent, "(roleattribute %s)", key);
		}

		if (ebitmap_cardinality(&role->roles) > 0) {
			cil_indent(indent);
			cil_printf("(roleattributeset %s (", key);
			ebitmap_for_each_bit(&role->roles, node, i) {
				if (!ebitmap_get_bit(&role->roles, i)) {
					continue;
				}
				cil_printf("%s ", pdb->p_role_val_to_name[i]);
			}
			cil_printf("))\n");
		}

		rc = typeset_to_names(indent, pdb, &role->types, &types, &num_types);
		if (rc != 0) {
			goto exit;
		}


		for (i = 0; i < num_types; i++) {
			cil_println(indent, "(roletype %s %s)", key, types[i]);
		}

		break;

	default:
		log_err("Unknown role type: %i", role->flavor);
		rc = -1;
		goto exit;
	}

	rc = 0;
exit:
	names_destroy(&types, &num_types);

	return rc;
}

static int type_to_cil(int indent, struct policydb *pdb, struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum, int scope)
{
	int rc = -1;
	struct type_datum *type = datum;

	switch(type->flavor) {
	case TYPE_TYPE:
		if (scope == SCOPE_DECL) {
			if (type->primary == 1) {
				cil_println(indent, "(type %s)", key);
				// object_r is implicit in checkmodule, but not with CIL,
				// create it as part of base
				cil_println(indent, "(roletype " DEFAULT_OBJECT " %s)", key);
			} else {
				cil_println(indent, "(typealias %s)", key);
				cil_println(indent, "(typealiasactual %s %s)", key, pdb->p_type_val_to_name[type->s.value - 1]);
			}
		}

		if (type->flags & TYPE_FLAGS_PERMISSIVE) {
			cil_println(indent, "(typepermissive %s)", key);
		}

		if (type->bounds > 0) {
			cil_println(indent, "(typebounds %s %s)", pdb->p_type_val_to_name[type->bounds - 1], key);
		}
		break;
	case TYPE_ATTRIB:
		if (scope == SCOPE_DECL) {
			cil_println(indent, "(typeattribute %s)", key);
		}

		if (ebitmap_cardinality(&type->types) > 0) {
			cil_indent(indent);
			cil_printf("(typeattributeset %s (", key);
			ebitmap_to_cil(pdb, &type->types, SYM_TYPES);
			cil_printf("))\n");
		}
		break;
	default:
		log_err("Unknown flavor (%i) of type %s", type->flavor, key);
		rc = -1;
		goto exit;
	}

	return 0;

exit:
	return rc;
}

static int user_to_cil(int indent, struct policydb *pdb, struct avrule_block *block, struct avrule_decl *UNUSED(decl), char *key, void *datum,  int scope)
{
	struct user_datum *user = datum;
	struct ebitmap roles = user->roles.roles;
	struct mls_semantic_level level = user->dfltlevel;
	struct mls_semantic_range range = user->range;
	struct ebitmap_node *node;
	uint32_t i;
	int sens_offset = 1;

	if (scope == SCOPE_DECL) {
		cil_println(indent, "(user %s)", key);
		// object_r is implicit in checkmodule, but not with CIL, create it
		// as part of base
		cil_println(indent, "(userrole %s " DEFAULT_OBJECT ")", key);
	}

	ebitmap_for_each_bit(&roles, node, i) {
		if (!ebitmap_get_bit(&roles, i)) {
			continue;
		}
		cil_println(indent, "(userrole %s %s)", key, pdb->p_role_val_to_name[i]);
	}

	if (block->flags & AVRULE_OPTIONAL) {
		// sensitivites in user statements in optionals do not have the
		// standard -1 offest
		sens_offset = 0;
	}

	cil_indent(indent);
	cil_printf("(userlevel %s ", key);
	if (pdb->mls) {
		semantic_level_to_cil(pdb, sens_offset, &level);
	} else {
		cil_printf(DEFAULT_LEVEL);
	}
	cil_printf(")\n");

	cil_indent(indent);
	cil_printf("(userrange %s (", key);
	if (pdb->mls) {
		semantic_level_to_cil(pdb, sens_offset, &range.level[0]);
		cil_printf(" ");
		semantic_level_to_cil(pdb, sens_offset, &range.level[1]);
	} else {
		cil_printf(DEFAULT_LEVEL " " DEFAULT_LEVEL);
	}
	cil_printf("))\n");


	return 0;
}

static int boolean_to_cil(int indent, struct policydb *UNUSED(pdb), struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum,  int scope)
{
	struct cond_bool_datum *boolean = datum;
	char *type;

	if (scope == SCOPE_DECL) {
		if (boolean->flags & COND_BOOL_FLAGS_TUNABLE) {
			type = "tunable";
		} else {
			type = "boolean";
		}

		cil_println(indent, "(%s %s %s)", type, key, boolean->state ? "true" : "false");
	}

	return 0;
}

static int sens_to_cil(int indent, struct policydb *pdb, struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum, int scope)
{
	struct level_datum *level = datum;

	if (scope == SCOPE_DECL) {
		if (!level->isalias) {
			cil_println(indent, "(sensitivity %s)", key);
		} else {
			cil_println(indent, "(sensitivityalias %s)", key);
			cil_println(indent, "(sensitivityaliasactual %s %s)", key, pdb->p_sens_val_to_name[level->level->sens - 1]);
		}
	}

	if (ebitmap_cardinality(&level->level->cat) > 0) {
		cil_indent(indent);
		cil_printf("(sensitivitycategory %s (", key);
		ebitmap_to_cil(pdb, &level->level->cat, SYM_CATS);
		cil_printf("))\n");
	}

	return 0;
}

static int sens_order_to_cil(int indent, struct policydb *pdb, struct ebitmap order)
{
	struct ebitmap_node *node;
	uint32_t i;

	if (ebitmap_cardinality(&order) == 0) {
		return 0;
	}

	cil_indent(indent);
	cil_printf("(sensitivityorder (");

	ebitmap_for_each_bit(&order, node, i) {
		if (!ebitmap_get_bit(&order, i)) {
			continue;
		}
		cil_printf("%s ", pdb->p_sens_val_to_name[i]);
	}

	cil_printf("))\n");

	return 0;
}

static int cat_to_cil(int indent, struct policydb *pdb, struct avrule_block *UNUSED(block), struct avrule_decl *UNUSED(decl), char *key, void *datum,  int scope)
{
	struct cat_datum *cat = datum;

	if (scope == SCOPE_REQ) {
		return 0;
	}

	if (!cat->isalias) {
		cil_println(indent, "(category %s)", key);
	} else {
		cil_println(indent, "(categoryalias %s)", key);
		cil_println(indent, "(categoryaliasactual %s %s)", key, pdb->p_cat_val_to_name[cat->s.value - 1]);
	}

	return 0;
}

static int cat_order_to_cil(int indent, struct policydb *pdb, struct ebitmap order)
{
	int rc = -1;
	struct ebitmap_node *node;
	uint32_t i;

	if (ebitmap_cardinality(&order) == 0) {
		rc = 0;
		goto exit;
	}

	cil_indent(indent);
	cil_printf("(categoryorder (");

	ebitmap_for_each_bit(&order, node, i) {
		if (!ebitmap_get_bit(&order, i)) {
			continue;
		}
		cil_printf("%s ", pdb->p_cat_val_to_name[i]);
	}

	cil_printf("))\n");

	return 0;
exit:
	return rc;
}

static int typealias_to_cil(char *key, void *data, void *arg)
{
	int rc = -1;
	struct type_datum *type = data;
	struct map_args *args = arg;

	if (type->primary != 1) {
		rc = type_to_cil(args->indent, args->pdb, args->block, args->decl, key, data, args->scope);
		if (rc != 0) {
			goto exit;
		}
	}

	return 0;

exit:
	return rc;
}

static int polcaps_to_cil(struct policydb *pdb)
{
	int rc = -1;
	struct ebitmap *map;
	struct ebitmap_node *node;
	uint32_t i;
	const char *name;

	map = &pdb->policycaps;

	ebitmap_for_each_bit(map, node, i) {
		if (!ebitmap_get_bit(map, i)) {
			continue;
		}
		name = sepol_polcap_getname(i);
		if (name == NULL) {
			log_err("Unknown policy capability id: %i", i);
			rc = -1;
			goto exit;
		}

		cil_println(0, "(policycap %s)", name);
	}

	return 0;
exit:
	return rc;
}

static int level_to_cil(struct policydb *pdb, struct mls_level *level)
{
	struct ebitmap *map = &level->cat;

	cil_printf("(%s", pdb->p_sens_val_to_name[level->sens - 1]);

	if (ebitmap_cardinality(map) > 0) {
		cil_printf("(");
		ebitmap_to_cil(pdb, map, SYM_CATS);
		cil_printf(")");
	}

	cil_printf(")");

	return 0;
}

static int context_to_cil(struct policydb *pdb, struct context_struct *con)
{
	cil_printf("(%s %s %s (",
		pdb->p_user_val_to_name[con->user - 1],
		pdb->p_role_val_to_name[con->role - 1],
		pdb->p_type_val_to_name[con->type - 1]);

	if (pdb->mls) {
		level_to_cil(pdb, &con->range.level[0]);
		cil_printf(" ");
		level_to_cil(pdb, &con->range.level[1]);
	} else {
		cil_printf(DEFAULT_LEVEL);
		cil_printf(" ");
		cil_printf(DEFAULT_LEVEL);
	}

	cil_printf("))");

	return 0;
}

static int ocontext_isid_to_cil(struct policydb *pdb, const char **sid_to_string, struct ocontext *isids)
{
	int rc = -1;

	struct ocontext *isid;

	struct sid_item {
		const char *sid_key;
		struct sid_item *next;
	};

	struct sid_item *head = NULL;
	struct sid_item *item = NULL;

	for (isid = isids; isid != NULL; isid = isid->next) {
		cil_println(0, "(sid %s)", sid_to_string[isid->sid[0]]);
		cil_printf("(sidcontext %s ", sid_to_string[isid->sid[0]]);
		context_to_cil(pdb, &isid->context[0]);
		cil_printf(")\n");

		// get the sid names in the correct order (reverse from the isids
		// ocontext) for sidorder statement
		item = malloc(sizeof(*item));
		if (item == NULL) {
			log_err("Out of memory");
			rc = -1;
			goto exit;
		}
		item->sid_key = sid_to_string[isid->sid[0]];
		item->next = head;
		head = item;
	}

	if (head != NULL) {
		cil_printf("(sidorder (");
		while (head) {
			cil_printf("%s ", head->sid_key);
			item = head->next;
			free(head);
			head = item;
		}
		cil_printf("))\n");
	}

	return 0;
exit:
	return rc;
}

static int ocontext_selinux_isid_to_cil(struct policydb *pdb, struct ocontext *isids)
{
	int rc = -1;

	// initial sid names aren't actually stored in the pp files, need to a have
	// a mapping, taken from the linux kernel
	static const char *selinux_sid_to_string[] = {
		"null",
		"kernel",
		"security",
		"unlabeled",
		"fs",
		"file",
		"file_labels",
		"init",
		"any_socket",
		"port",
		"netif",
		"netmsg",
		"node",
		"igmp_packet",
		"icmp_socket",
		"tcp_socket",
		"sysctl_modprobe",
		"sysctl",
		"sysctl_fs",
		"sysctl_kernel",
		"sysctl_net",
		"sysctl_net_unix",
		"sysctl_vm",
		"sysctl_dev",
		"kmod",
		"policy",
		"scmp_packet",
		"devnull",
		NULL
	};

	rc = ocontext_isid_to_cil(pdb, selinux_sid_to_string, isids);
	if (rc != 0) {
		goto exit;
	}

	return 0;

exit:
	return rc;
}

static int ocontext_selinux_fs_to_cil(struct policydb *UNUSED(pdb), struct ocontext *fss)
{
	if (fss != NULL) {
		log_err("Warning: 'fscon' statment unsupported in CIL. Dropping from output.");
	}

	return 0;
}

static int ocontext_selinux_port_to_cil(struct policydb *pdb, struct ocontext *portcons)
{
	int rc = -1;
	struct ocontext *portcon;
	char *protocol;
	uint16_t high;
	uint16_t low;

	for (portcon = portcons; portcon != NULL; portcon = portcon->next) {

		switch (portcon->u.port.protocol) {
		case IPPROTO_TCP: protocol = "tcp"; break;
		case IPPROTO_UDP: protocol = "udp"; break;
		default:
			log_err("Unknown portcon protocol: %i", portcon->u.port.protocol);
			rc = -1;
			goto exit;
		}

		low = portcon->u.port.low_port;
		high = portcon->u.port.high_port;

		if (low == high) {
			cil_printf("(portcon %s %i ", protocol, low);
		} else {
			cil_printf("(portcon %s (%i %i) ", protocol, low, high);
		}

		context_to_cil(pdb, &portcon->context[0]);

		cil_printf(")\n");
	}

	return 0;
exit:
	return rc;
}

static int ocontext_selinux_netif_to_cil(struct policydb *pdb, struct ocontext *netifs)
{
	struct ocontext *netif;

	for (netif = netifs; netif != NULL; netif = netif->next) {
		cil_printf("(netifcon %s ", netif->u.name);
		context_to_cil(pdb, &netif->context[0]);

		cil_printf(" ");
		context_to_cil(pdb, &netif->context[1]);
		cil_printf(")\n");
	}

	return 0;
}

static int ocontext_selinux_node_to_cil(struct policydb *pdb, struct ocontext *nodes)
{
	int rc = -1;
	struct ocontext *node;
	char addr[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];

	for (node = nodes; node != NULL; node = node->next) {
		if (inet_ntop(AF_INET, &node->u.node.addr, addr, INET_ADDRSTRLEN) == NULL) {
			log_err("Nodecon address is invalid: %s", strerror(errno));
			rc = -1;
			goto exit;
		}

		if (inet_ntop(AF_INET, &node->u.node.mask, mask, INET_ADDRSTRLEN) == NULL) {
			log_err("Nodecon mask is invalid: %s", strerror(errno));
			rc = -1;
			goto exit;
		}

		cil_printf("(nodecon %s %s ", addr, mask);

		context_to_cil(pdb, &node->context[0]);

		cil_printf(")\n");
	}

	return 0;
exit:
	return rc;
}

static int ocontext_selinux_node6_to_cil(struct policydb *pdb, struct ocontext *nodes)
{
	int rc = -1;
	struct ocontext *node;
	char addr[INET6_ADDRSTRLEN];
	char mask[INET6_ADDRSTRLEN];

	for (node = nodes; node != NULL; node = node->next) {
		if (inet_ntop(AF_INET6, &node->u.node6.addr, addr, INET6_ADDRSTRLEN) == NULL) {
			log_err("Nodecon address is invalid: %s", strerror(errno));
			rc = -1;
			goto exit;
		}

		if (inet_ntop(AF_INET6, &node->u.node6.mask, mask, INET6_ADDRSTRLEN) == NULL) {
			log_err("Nodecon mask is invalid: %s", strerror(errno));
			rc = -1;
			goto exit;
		}

		cil_printf("(nodecon %s %s ", addr, mask);

		context_to_cil(pdb, &node->context[0]);

		cil_printf(")\n");
	}

	return 0;
exit:
	return rc;
}


static int ocontext_selinux_fsuse_to_cil(struct policydb *pdb, struct ocontext *fsuses)
{
	int rc = -1;
	struct ocontext *fsuse;
	char *behavior;


	for (fsuse = fsuses; fsuse != NULL; fsuse = fsuse->next) {
		switch (fsuse->v.behavior) {
		case SECURITY_FS_USE_XATTR: behavior = "xattr"; break;
		case SECURITY_FS_USE_TRANS: behavior = "trans"; break;
		case SECURITY_FS_USE_TASK:  behavior = "task"; break;
		default:
			log_err("Unknown fsuse behavior: %i", fsuse->v.behavior);
			rc = -1;
			goto exit;
		}

		cil_printf("(fsuse %s %s ", behavior, fsuse->u.name);

		context_to_cil(pdb, &fsuse->context[0]);

		cil_printf(")\n");

	}

	return 0;
exit:
	return rc;
}


static int ocontext_xen_isid_to_cil(struct policydb *pdb, struct ocontext *isids)
{
	int rc = -1;

	// initial sid names aren't actually stored in the pp files, need to a have
	// a mapping, taken from the xen kernel
	static const char *xen_sid_to_string[] = {
		"null",
		"xen",
		"dom0",
		"domio",
		"domxen",
		"unlabeled",
		"security",
		"ioport",
		"iomem",
		"irq",
		"device",
		NULL,
	};

	rc = ocontext_isid_to_cil(pdb, xen_sid_to_string, isids);
	if (rc != 0) {
		goto exit;
	}

	return 0;

exit:
	return rc;
}

static int ocontext_xen_pirq_to_cil(struct policydb *pdb, struct ocontext *pirqs)
{
	struct ocontext *pirq;

	for (pirq = pirqs; pirq != NULL; pirq = pirq->next) {
		cil_printf("(pirqcon %i ", pirq->u.pirq);
		context_to_cil(pdb, &pirq->context[0]);
		cil_printf(")\n");
	}

	return 0;
}

static int ocontext_xen_ioport_to_cil(struct policydb *pdb, struct ocontext *ioports)
{
	struct ocontext *ioport;
	uint32_t low;
	uint32_t high;

	for (ioport = ioports; ioport != NULL; ioport = ioport->next) {
		low = ioport->u.ioport.low_ioport;
		high = ioport->u.ioport.high_ioport;

		if (low == high) {
			cil_printf("(ioportcon %i ", low);
		} else {
			cil_printf("(ioportcon (%i %i) ", low, high);
		}

		context_to_cil(pdb, &ioport->context[0]);

		cil_printf(")\n");
	}

	return 0;
}

static int ocontext_xen_iomem_to_cil(struct policydb *pdb, struct ocontext *iomems)
{
	struct ocontext *iomem;
	uint32_t low;
	uint32_t high;

	for (iomem = iomems; iomem != NULL; iomem = iomem->next) {
		low = iomem->u.iomem.low_iomem;
		high = iomem->u.iomem.high_iomem;

		if (low == high) {
			cil_printf("(iomemcon %#lX ", low);
		} else {
			cil_printf("(iomemcon (%#lX %#lX) ", low, high);
		}

		context_to_cil(pdb, &iomem->context[0]);

		cil_printf(")\n");
	}

	return 0;
}

static int ocontext_xen_pcidevice_to_cil(struct policydb *pdb, struct ocontext *pcids)
{
	struct ocontext *pcid;

	for (pcid = pcids; pcid != NULL; pcid = pcid->next) {
		cil_printf("(pcidevicecon %#lx ", pcid->u.device);
		context_to_cil(pdb, &pcid->context[0]);
		cil_printf(")\n");
	}

	return 0;
}

static int ocontexts_to_cil(struct policydb *pdb)
{
	int rc = -1;
	int ocon;

	static int (**ocon_funcs)(struct policydb *pdb, struct ocontext *ocon);
	static int (*ocon_selinux_funcs[OCON_NUM])(struct policydb *pdb, struct ocontext *ocon) = {
		ocontext_selinux_isid_to_cil,
		ocontext_selinux_fs_to_cil,
		ocontext_selinux_port_to_cil,
		ocontext_selinux_netif_to_cil,
		ocontext_selinux_node_to_cil,
		ocontext_selinux_fsuse_to_cil,
		ocontext_selinux_node6_to_cil,
	};
	static int (*ocon_xen_funcs[OCON_NUM])(struct policydb *pdb, struct ocontext *ocon) = {
		ocontext_xen_isid_to_cil,
		ocontext_xen_pirq_to_cil,
		ocontext_xen_ioport_to_cil,
		ocontext_xen_iomem_to_cil,
		ocontext_xen_pcidevice_to_cil,
		NULL,
		NULL,
	};

	switch (pdb->target_platform) {
	case SEPOL_TARGET_SELINUX:
		ocon_funcs = ocon_selinux_funcs;
		break;
	case SEPOL_TARGET_XEN:
		ocon_funcs = ocon_xen_funcs;
		break;
	default:
		log_err("Unknown target platform: %i", pdb->target_platform);
		rc = -1;
		goto exit;
	}

	for (ocon = 0; ocon < OCON_NUM; ocon++) {
		if (ocon_funcs[ocon] != NULL) {
			rc = ocon_funcs[ocon](pdb, pdb->ocontexts[ocon]);
			if (rc != 0) {
				goto exit;
			}
		}
	}

	return 0;
exit:
	return rc;
}

static int genfscon_to_cil(struct policydb *pdb)
{
	struct genfs *genfs;
	struct ocontext *ocon;

	for (genfs = pdb->genfs; genfs != NULL; genfs = genfs->next) {
		for (ocon = genfs->head; ocon != NULL; ocon = ocon->next) {
			cil_printf("(genfscon %s %s ", genfs->fstype, ocon->u.name);
			context_to_cil(pdb, &ocon->context[0]);
			cil_printf(")\n");
		}
	}

	return 0;
}

static int level_string_to_cil(char *levelstr)
{
	int rc = -1;
	char *sens = NULL;
	char *cats = NULL;
	int matched;
	char *saveptr = NULL;
	char *token = NULL;
	char *ranged = NULL;

	matched = sscanf(levelstr, "%m[^:]:%ms", &sens, &cats);
	if (matched < 1 || matched > 2) {
		log_err("Invalid level: %s", levelstr);
		rc = -1;
		goto exit;
	}

	cil_printf("(%s", sens);

	if (matched == 2) {
		cil_printf("(");
		token = strtok_r(cats, ",", &saveptr);
		while (token != NULL) {
			ranged = strchr(token, '.');
			if (ranged == NULL) {
				cil_printf("%s ", token);
			} else {
				*ranged = '\0';
				cil_printf("(range %s %s) ", token, ranged + 1);
			}
			token = strtok_r(NULL, ",", &saveptr);
		}
		cil_printf(")");
	}

	cil_printf(")");

	rc = 0;
exit:
	free(sens);
	free(cats);
	return rc;
}

static int level_range_string_to_cil(char *levelrangestr)
{
	char *ranged = NULL;
	char *low;
	char *high;

	ranged = strchr(levelrangestr, '-');
	if (ranged == NULL) {
		low = high = levelrangestr;
	} else {
		*ranged = '\0';
		low = levelrangestr;
		high = ranged + 1;
	}

	level_string_to_cil(low);
	cil_printf(" ");
	level_string_to_cil(high);

	return 0;
}

static int context_string_to_cil(char *contextstr)
{
	int rc = -1;
	int matched;
	char *user = NULL;
	char *role = NULL;
	char *type = NULL;
	char *level = NULL;

	matched = sscanf(contextstr, "%m[^:]:%m[^:]:%m[^:]:%ms", &user, &role, &type, &level);
	if (matched < 3 || matched > 4) {
		log_err("Invalid context: %s", contextstr);
		rc = -1;
		goto exit;
	}

	cil_printf("(%s %s %s (", user, role, type);

	if (matched == 3) {
		cil_printf(DEFAULT_LEVEL);
		cil_printf(" ");
		cil_printf(DEFAULT_LEVEL);
	} else {
		level_range_string_to_cil(level);
	}

	cil_printf("))");

	rc = 0;

exit:
	free(user);
	free(role);
	free(type);
	free(level);

	return rc;
}

static int seusers_to_cil(struct sepol_module_package *mod_pkg)
{
	int rc = -1;
	FILE *fp = NULL;
	char *seusers = sepol_module_package_get_seusers(mod_pkg);
	size_t seusers_len = sepol_module_package_get_seusers_len(mod_pkg);
	size_t len = 0;
	char *line = NULL;
	ssize_t line_len = 0;
	char *buf = NULL;

	char *user = NULL;
	char *seuser = NULL;
	char *level = NULL;
	int matched;

	if (seusers_len == 0) {
		return 0;
	}

	fp = fmemopen(seusers, seusers_len, "r");

	while ((line_len = getline(&line, &len, fp)) != -1) {
		buf = line;
		buf[line_len - 1] = '\0';
		while (*buf && isspace(buf[0])) {
			buf++;
		}
		if (buf[0] == '#' || buf[0] == '\0') {
			continue;
		}

		matched = sscanf(buf, "%m[^:]:%m[^:]:%ms", &user, &seuser, &level);

		if (matched < 2 || matched > 3) {
			log_err("Invalid seuser line: %s", line);
			rc = -1;
			goto exit;
		}

		if (!strcmp(user, "__default__")) {
			cil_printf("(selinuxuserdefault %s (", seuser);
		} else {
			cil_printf("(selinuxuser %s %s (", user, seuser);
		}

		switch (matched) {
		case 2:
			cil_printf("systemlow systemlow");
			break;
		case 3:
			level_range_string_to_cil(level);
			break;
		}

		cil_printf("))\n");

		free(user);
		free(seuser);
		free(level);
		user = seuser = level = NULL;
	}
	if (ferror(fp)) {
		cil_printf("Failed to read seusers\n");
		rc = -1;
		goto exit;
	}

	rc = 0;

exit:
	if (fp != NULL) {
		fclose(fp);
	}
	free(line);
	free(user);
	free(seuser);
	free(level);

	return rc;
}

static int netfilter_contexts_to_cil(struct sepol_module_package *mod_pkg)
{
	size_t netcons_len = sepol_module_package_get_netfilter_contexts_len(mod_pkg);

	if (netcons_len > 0) {
		log_err("Warning: netfilter_contexts are unsupported in CIL. Dropping from output.");
	}

	return 0;
}

static int user_extra_to_cil(struct sepol_module_package *mod_pkg)
{
	int rc = -1;
	char *userx = sepol_module_package_get_user_extra(mod_pkg);
	size_t userx_len = sepol_module_package_get_user_extra_len(mod_pkg);
	FILE *fp = NULL;
	size_t len = 0;
	char *line = NULL;
	ssize_t line_len = 0;
	int matched;
	char *user = NULL;
	char *prefix = NULL;

	if (userx_len == 0) {
		return 0;
	}

	fp = fmemopen(userx, userx_len, "r");

	while ((line_len = getline(&line, &len, fp)) != -1) {
		line[line_len - 1] = '\0';

		matched = sscanf(line, "user %ms prefix %m[^;];", &user, &prefix);
		if (matched != 2) {
			rc = -1;
			log_err("Invalid file context line: %s", line);
			goto exit;
		}

		cil_println(0, "(userprefix %s %s)", user, prefix);
		free(user);
		free(prefix);
		user = prefix = NULL;
	}

	if (ferror(fp)) {
		cil_printf("Failed to read user_extra\n");
		rc = -1;
		goto exit;
	}

	rc = 0;
exit:
	if (fp != NULL) {
		fclose(fp);
	}
	free(line);
	free(user);
	free(prefix);

	return rc;
}

static int file_contexts_to_cil(struct sepol_module_package *mod_pkg)
{
	int rc = -1;
	char *fc = sepol_module_package_get_file_contexts(mod_pkg);
	size_t fc_len = sepol_module_package_get_file_contexts_len(mod_pkg);
	FILE *fp = NULL;
	size_t len = 0;
	char *line = NULL;
	char *buf = NULL;
	ssize_t line_len = 0;
	int matched;
	char *regex = NULL;
	char *mode = NULL;
	char *context = NULL;
	char *cilmode;

	if (fc_len == 0) {
		return 0;
	}

	fp = fmemopen(fc, fc_len, "r");
	while ((line_len = getline(&line, &len, fp)) != -1) {
		buf = line;
		buf[line_len - 1] = '\0';
		while (*buf && isspace(buf[0])) {
			buf++;
		}
		if (buf[0] == '#' || buf[0] == '\0') {
			continue;
		}

		matched = sscanf(buf, "%ms %ms %ms", &regex, &mode, &context);
		if (matched < 2 || matched > 3) {
			rc = -1;
			log_err("Invalid file context line: %s", line);
			goto exit;
		}

		if (matched == 2) {
			context = mode;
			mode = NULL;
		}

		if (mode == NULL) {
			cilmode = "any";
		} else if (!strcmp(mode, "--")) {
			cilmode = "file";
		} else if (!strcmp(mode, "-d")) {
			cilmode = "dir";
		} else if (!strcmp(mode, "-c")) {
			cilmode = "char";
		} else if (!strcmp(mode, "-b")) {
			cilmode = "block";
		} else if (!strcmp(mode, "-s")) {
			cilmode = "socket";
		} else if (!strcmp(mode, "-p")) {
			cilmode = "pipe";
		} else if (!strcmp(mode, "-l")) {
			cilmode = "symlink";
		}

		cil_printf("(filecon \"%s\" \"\" %s ", regex, cilmode);

		if (!strcmp(context, "<<none>>")) {
			cil_printf("()");
		} else {
			context_string_to_cil(context);
		}

		cil_printf(")\n");

		free(regex);
		free(mode);
		free(context);
		regex = mode = context = NULL;
	}

	if (ferror(fp)) {
		cil_printf("Failed to read user_extra\n");
		rc = -1;
		goto exit;
	}

	rc = 0;
exit:
	free(line);
	free(regex);
	free(mode);
	free(context);
	if (fp != NULL) {
		fclose(fp);
	}

	return rc;
}


static int (*func_to_cil[SYM_NUM])(int indent, struct policydb *pdb, struct avrule_block *block, struct avrule_decl *decl, char *key, void *datum, int scope) = {
	NULL,	// commons, only stored in the global symtab, handled elsewhere
	class_to_cil,
	role_to_cil,
	type_to_cil,
	user_to_cil,
	boolean_to_cil,
	sens_to_cil,
	cat_to_cil
};

static int declared_scopes_to_cil(int indent, struct policydb *pdb, struct avrule_block *block, struct avrule_decl *decl)
{
	int rc = -1;
	struct ebitmap map;
	struct ebitmap_node *node;
	unsigned int i;
	char * key;
	struct scope_datum *scope;
	int sym;
	void *datum;

	for (sym = 0; sym < SYM_NUM; sym++) {
		if (func_to_cil[sym] == NULL) {
			continue;
		}

		map = decl->declared.scope[sym];
		ebitmap_for_each_bit(&map, node, i) {
			if (!ebitmap_get_bit(&map, i)) {
				continue;
			}
			key = pdb->sym_val_to_name[sym][i];
			datum = hashtab_search(pdb->symtab[sym].table, key);
			if (datum == NULL) {
				rc = -1;
				goto exit;
			}
			scope = hashtab_search(pdb->scope[sym].table, key);
			if (scope == NULL) {
				rc = -1;
				goto exit;
			}
			rc = func_to_cil[sym](indent, pdb, block, decl, key, datum, scope->scope);
			if (rc != 0) {
				goto exit;
			}
		}

		if (sym == SYM_CATS) {
			rc = cat_order_to_cil(indent, pdb, map);
			if (rc != 0) {
				goto exit;
			}
		}

		if (sym == SYM_LEVELS) {
			rc = sens_order_to_cil(indent, pdb, map);
			if (rc != 0) {
				goto exit;
			}
		}
	}

	return 0;
exit:
	return rc;
}

static int required_scopes_to_cil(int indent, struct policydb *pdb, struct avrule_block *block, struct avrule_decl *decl)
{
	int rc = -1;
	struct ebitmap map;
	struct ebitmap_node *node;
	unsigned int i;
	char * key;
	int sym;
	void *datum;

	for (sym = 0; sym < SYM_NUM; sym++) {
		if (func_to_cil[sym] == NULL) {
			continue;
		}

		map = decl->required.scope[sym];
		ebitmap_for_each_bit(&map, node, i) {
			if (!ebitmap_get_bit(&map, i)) {
				continue;
			}
			key = pdb->sym_val_to_name[sym][i];
			datum = hashtab_search(pdb->symtab[sym].table, key);
			if (datum == NULL) {
				rc = -1;
				goto exit;
			}
			rc = func_to_cil[sym](indent, pdb, block, decl, key, datum, SCOPE_REQ);
			if (rc != 0) {
				goto exit;
			}
		}
	}

	return 0;
exit:
	return rc;
}


static int additive_scopes_to_cil_map(char *key, void *data, void *arg)
{
	int rc = -1;
	struct map_args *args = arg;

	rc = func_to_cil[args->sym_index](args->indent, args->pdb, args->block, args->decl, key, data, SCOPE_REQ);
	if (rc != 0) {
		goto exit;
	}

	return 0;

exit:
	return rc;
}

static int additive_scopes_to_cil(int indent, struct policydb *pdb, struct avrule_block *block, struct avrule_decl *decl)
{
	int rc = -1;
	struct map_args args;
	args.pdb = pdb;
	args.block = block;
	args.decl = decl;
	args.indent = indent;

	for (args.sym_index = 0; args.sym_index < SYM_NUM; args.sym_index++) {
		rc = hashtab_map(decl->symtab[args.sym_index].table, additive_scopes_to_cil_map, &args);
		if (rc != 0) {
			goto exit;
		}
	}

	return 0;

exit:
	return rc;
}

static int is_scope_superset(struct scope_index *sup, struct scope_index *sub)
{
	// returns 1 if sup is a superset of sub, returns 0 otherwise

	int rc = 0;

	uint32_t i;
	struct ebitmap sup_map;
	struct ebitmap sub_map;
	struct ebitmap res;

	ebitmap_init(&res);

	for (i = 0; i < SYM_NUM; i++) {
		sup_map = sup->scope[i];
		sub_map = sub->scope[i];

		ebitmap_and(&res, &sup_map, &sub_map);
		if (!ebitmap_cmp(&res, &sub_map)) {
			goto exit;
		}
		ebitmap_destroy(&res);
	}

	if (sup->class_perms_len < sub->class_perms_len) {
		goto exit;
	}

	for (i = 0; i < sub->class_perms_len; i++) {
		sup_map = sup->class_perms_map[i];
		sub_map = sub->class_perms_map[i];

		ebitmap_and(&res, &sup_map, &sub_map);
		if (!ebitmap_cmp(&res, &sub_map)) {
			goto exit;
		}
		ebitmap_destroy(&res);
	}

	rc = 1;

exit:

	ebitmap_destroy(&res);
	return rc;
}

static int decl_roles_to_cil(int indent, struct policydb *pdb, struct avrule_decl *decl, struct role_datum **decl_roles, uint32_t num_decl_roles)
{
	int rc = -1;
	uint32_t i, j, k;
	char **types = NULL;
	uint32_t num_types = 0;
	struct role_datum *role;
	struct scope_datum *scope;

	for (i = 0; i < num_decl_roles; i++) {
		role = decl_roles[i];

		rc = typeset_to_names(indent, pdb, &role->types, &types, &num_types);
		if (rc != 0) {
			goto exit;
		}

		for (j = 0; j < num_types; j++) {
			scope = hashtab_search(pdb->p_types_scope.table, types[j]);
			if (scope == NULL) {
				rc = -1;
				goto exit;
			}
			for (k = 0; k < scope->decl_ids_len; k++) {
				if (scope->decl_ids[k] == decl->decl_id) {
					cil_println(indent, "(roletype %s %s)", pdb->p_role_val_to_name[role->s.value - 1], types[j]);
				}
			}
		}

		names_destroy(&types, &num_types);
	}

	rc = 0;

exit:
	names_destroy(&types, &num_types);

	return rc;
}

struct decl_roles_args {
	struct policydb *pdb;
	int count;
	struct role_datum **decl_roles;
};

static int count_decl_roles(char *key, void *UNUSED(datum), void *arg)
{
	struct scope_datum *scope;
	struct decl_roles_args *args = arg;

	if (!strcmp(key, DEFAULT_OBJECT)) {
		return 0;
	}

	scope = hashtab_search(args->pdb->p_roles_scope.table, key);
	if (scope == NULL || scope->scope != SCOPE_DECL) {
		return 0;
	}
	args->count++;

	return 0;
}

static int fill_decl_roles(char *key, void *datum, void *arg)
{
	struct scope_datum *scope;
	struct decl_roles_args *args = arg;

	if (!strcmp(key, DEFAULT_OBJECT)) {
		return 0;
	}

	scope = hashtab_search(args->pdb->p_roles_scope.table, key);
	if (scope == NULL || scope->scope != SCOPE_DECL) {
		return 0;
	}

	args->decl_roles[args->count++] = datum;

	return 0;
}

static int get_decl_roles(struct policydb *pdb, struct role_datum ***decl_roles, int *num_decl_roles)
{
	int rc = -1;
	uint32_t num;
	struct role_datum **roles;
	struct decl_roles_args args;
	args.pdb = pdb;

	args.count = 0;
	rc = hashtab_map(pdb->p_roles.table, count_decl_roles, &args);
	if (rc != 0) {
		goto exit;
	}
	num = args.count;

	roles = malloc(sizeof(*roles) * num);
	if (roles == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}

	args.count = 0;
	args.decl_roles = roles;
	rc = hashtab_map(pdb->p_roles.table, fill_decl_roles, &args);
	if (rc != 0) {
		goto exit;
	}

	*decl_roles = roles;
	*num_decl_roles = num;

	return 0;

exit:
	free(roles);
	return rc;
}


static int blocks_to_cil(struct policydb *pdb)
{
	int rc = -1;
	struct avrule_block *block;
	struct avrule_decl *decl;
	int indent = 0;
	struct stack *stack;
	int num_decl_roles = 0;
	struct role_datum **decl_roles = NULL;

	rc = get_decl_roles(pdb, &decl_roles, &num_decl_roles);
	if (rc != 0) {
		goto exit;
	}

	rc = stack_init(&stack);
	if (rc != 0) {
		goto exit;
	}

	for (block = pdb->global; block != NULL; block = block->next) {
		decl = block->branch_list;
		if (decl == NULL) {
			continue;
		}

		if (decl->next != NULL) {
			log_err("Warning: 'else' blocks in optional statements are unsupported in CIL. Dropping from output.");
		}

		if (block->flags & AVRULE_OPTIONAL) {
			while (stack->pos > 0 && !is_scope_superset(&decl->required, stack_peek(stack))) {
				stack_pop(stack);
				indent--;
				cil_println(indent, ")");
			}

			cil_println(indent, "(optional %s_optional_%i", pdb->name, decl->decl_id);
			indent++;
		}

		stack_push(stack, &decl->required);

		if (stack->pos == 0) {
			// type aliases and commons are only stored in the global symtab.
			// However, to get scoping correct, we assume they are in the
			// global block
			struct map_args args;
			args.pdb = pdb;
			args.block = block;
			args.decl = decl;
			args.indent = 0;
			args.scope = SCOPE_DECL;

			rc = hashtab_map(pdb->p_types.table, typealias_to_cil, &args);
			if (rc != 0) {
				goto exit;
			}

			rc = hashtab_map(pdb->p_commons.table, common_to_cil, &args);
			if (rc != 0) {
				goto exit;
			}
		}

		rc = decl_roles_to_cil(indent, pdb, decl, decl_roles, num_decl_roles);
		if (rc != 0) {
			goto exit;
		}

		rc = declared_scopes_to_cil(indent, pdb, block, decl);
		if (rc != 0) {
			goto exit;
		}

		rc = required_scopes_to_cil(indent, pdb, block, decl);
		if (rc != 0) {
			goto exit;
		}

		rc = additive_scopes_to_cil(indent, pdb, block, decl);
		if (rc != 0) {
			goto exit;
		}

		rc = avrule_list_to_cil(indent, pdb, decl->avrules);
		if (rc != 0) {
			goto exit;
		}

		rc = role_trans_to_cil(indent, pdb, decl->role_tr_rules);
		if (rc != 0) {
			goto exit;
		}

		rc = role_allows_to_cil(indent, pdb, decl->role_allow_rules);
		if (rc != 0) {
			goto exit;
		}

		rc = range_trans_to_cil(indent, pdb, decl->range_tr_rules);
		if (rc != 0) {
			goto exit;
		}

		rc = filename_trans_to_cil(indent, pdb, decl->filename_trans_rules);
		if (rc != 0) {
			goto exit;
		}

		rc = cond_list_to_cil(indent, pdb, decl->cond_list);
		if (rc != 0) {
			goto exit;
		}

	}

	while (indent > 0) {
		indent--;
		cil_println(indent, ")");
	}

	rc = 0;

exit:
	stack_destroy(&stack);
	free(decl_roles);

	return rc;
}

static int handle_unknown_to_cil(struct policydb *pdb)
{
	int rc = -1;
	char *hu;

	switch (pdb->handle_unknown) {
	case SEPOL_DENY_UNKNOWN:
		hu = "deny";
		break;
	case SEPOL_REJECT_UNKNOWN:
		hu = "reject";
		break;
	case SEPOL_ALLOW_UNKNOWN:
		hu = "allow";
		break;
	default:
		log_err("Unknown value for handle-unknown: %i", pdb->handle_unknown);
		rc = -1;
		goto exit;
	}

	cil_println(0, "(handleunknown %s)", hu);

	return 0;

exit:
	return rc;
}

static int generate_mls(struct policydb *pdb)
{
	char *mls_str = pdb->mls ? "true" : "false";
	cil_println(0, "(mls %s)", mls_str);

	return 0;
}

static int generate_default_level(void)
{
	cil_println(0, "(sensitivity s0)");
	cil_println(0, "(sensitivityorder (s0))");
	cil_println(0, "(level " DEFAULT_LEVEL " (s0))");

	return 0;
}

static int generate_default_object(void)
{
	cil_println(0, "(role " DEFAULT_OBJECT ")");

	return 0;
}

static int fix_module_name(struct policydb *pdb)
{
	char *letter;
	int rc = -1;

	// The base module doesn't have its name set, but we use that for some
	// autogenerated names, like optionals and attributes, to prevent naming
	// collisions. However, they sometimes need to be fixed up.

	// the base module isn't given a name, so just call it "base"
	if (pdb->policy_type == POLICY_BASE) {
		pdb->name = strdup("base");
		if (pdb->name == NULL) {
			log_err("Out of memory");
			rc = -1;
			goto exit;
		}
	}

	// CIL is more restrictive in module names than checkmodule. Convert bad
	// characters to underscores
	for (letter = pdb->name; *letter != '\0'; letter++) {
		if (isalnum(*letter)) {
			continue;
		}

		*letter = '_';
	}

	return 0;
exit:
	return rc;
}

static int module_package_to_cil(struct sepol_module_package *mod_pkg)
{
	int rc = -1;
	struct sepol_policydb *pdb;

	pdb = sepol_module_package_get_policy(mod_pkg);
	if (pdb == NULL) {
		log_err("Failed to get policydb");
		rc = -1;
		goto exit;
	}

	if (pdb->p.policy_type != SEPOL_POLICY_BASE &&
		pdb->p.policy_type != SEPOL_POLICY_MOD) {
		log_err("Policy pakcage is not a base or module");
		rc = -1;
		goto exit;
	}

	rc = fix_module_name(&pdb->p);
	if (rc != 0) {
		goto exit;
	}

	if (pdb->p.policy_type == SEPOL_POLICY_BASE && !pdb->p.mls) {
		// If this is a base non-mls policy, we need to define a default level
		// range that can be used for contexts by other non-mls modules, since
		// CIL requires that all contexts have a range, even if they are
		// ignored as in non-mls policies
		rc = generate_default_level();
		if (rc != 0) {
			goto exit;
		}
	}

	if (pdb->p.policy_type == SEPOL_POLICY_BASE) {
		// object_r is implicit in checkmodule, but not with CIL, create it
		// as part of base
		rc = generate_default_object();
		if (rc != 0) {
			goto exit;
		}

		// handle_unknown is used from only the base module
		rc = handle_unknown_to_cil(&pdb->p);
		if (rc != 0) {
			goto exit;
		}

		// mls is used from only the base module	
		rc = generate_mls(&pdb->p);
		if (rc != 0) {
			goto exit;
		}
	}

	rc = polcaps_to_cil(&pdb->p);
	if (rc != 0) {
		goto exit;
	}

	rc = ocontexts_to_cil(&pdb->p);
	if (rc != 0) {
		goto exit;
	}

	rc = genfscon_to_cil(&pdb->p);
	if (rc != 0) {
		goto exit;
	}

	rc = seusers_to_cil(mod_pkg);
	if (rc != 0) {
		goto exit;
	}

	rc = netfilter_contexts_to_cil(mod_pkg);
	if (rc != 0) {
		goto exit;
	}

	rc = user_extra_to_cil(mod_pkg);
	if (rc != 0) {
		goto exit;
	}

	rc = file_contexts_to_cil(mod_pkg);
	if (rc != 0) {
		goto exit;
	}

	// now print everything that is scoped
	rc = blocks_to_cil(&pdb->p);
	if (rc != 0) {
		goto exit;
	}

	return 0;

exit:
	return rc;
}

static int fp_to_buffer(FILE *fp, char **data, size_t *data_len)
{
	int rc = -1;
	char *d = NULL;
	size_t d_len = 0;
	size_t read_len = 0;
	size_t max_len = 1 << 17; // start at 128KB, this is enough to hold about half of all the existing pp files

	d = malloc(max_len);
	if (d == NULL) {
		log_err("Out of memory");
		rc = -1;
		goto exit;
	}

	while ((read_len = fread(d + d_len, 1, max_len - d_len, fp)) > 0) {
		d_len += read_len;
		if (d_len == max_len) {
			max_len *= 2;
			d = realloc(d, max_len);
			if (d == NULL) {
				log_err("Out of memory");
				rc = -1;
				goto exit;
			}
		}
	}

	if (ferror(fp) != 0) {
		log_err("Failed to read pp file");
		rc = -1;
		goto exit;
	}

	*data = d;
	*data_len = d_len;

	return 0;

exit:
	free(d);
	return rc;
}

static int ppfile_to_module_package(FILE *fp, struct sepol_module_package **mod_pkg)
{
	int rc = -1;
	FILE *f = NULL;
	struct sepol_policy_file *pf = NULL;
	struct sepol_module_package *pkg = NULL;
	char *data = NULL;
	size_t data_len;
	int fd;
	struct stat sb;

	rc = sepol_policy_file_create(&pf);
	if (rc != 0) {
		log_err("Failed to create policy file");
		goto exit;
	}

	fd = fileno(fp);
	if (fstat(fd, &sb) == -1) {
		rc = -1;
		goto exit;
	}

	if (S_ISFIFO(sb.st_mode) || S_ISSOCK(sb.st_mode)) {
		// libsepol fails when trying to read a policy package from a pipe or a
		// socket due its use of lseek. In this case, read the data into a
		// buffer and provide that to libsepol
		rc = fp_to_buffer(fp, &data, &data_len);
		if (rc != 0) {
			goto exit;
		}

		sepol_policy_file_set_mem(pf, data, data_len);
	} else {
		sepol_policy_file_set_fp(pf, fp);
	}

	rc = sepol_module_package_create(&pkg);
	if (rc != 0) {
		log_err("Failed to create module package");
		goto exit;
	}

	rc = sepol_module_package_read(pkg, pf, 0);
	if (rc != 0) {
		log_err("Failed to read policy package");
		goto exit;
	}

	*mod_pkg = pkg;

exit:
	free(data);

	sepol_policy_file_free(pf);
	if (f != NULL) {
		fclose(f);
	}

	if (rc != 0) {
		sepol_module_package_free(pkg);
	}

	return rc;
}

static void usage(int err)
{
	fprintf(stderr, "Usage: %s [OPTIONS] [IN_FILE [OUT_FILE]]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "Read an SELinux policy package (.pp) and output the equivilent CIL.\n");
	fprintf(stderr, "If IN_FILE is not provided or is -, read SELinux policy package from\n");
	fprintf(stderr, "standard input. If OUT_FILE is not provided or is -, output CIL to\n");
	fprintf(stderr, "standard output.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help      print this message and exit\n");
	exit(err);
}

int main(int argc, char **argv)
{
	int rc = -1;
	int opt;
	static struct option long_opts[] = {
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	struct sepol_module_package *mod_pkg = NULL;
	FILE *in = NULL;
	FILE *out = NULL;
	int outfd = -1;

	// ignore sigpipe so we can check the return code of write, and potentially
	// return a more helpful error message
	signal(SIGPIPE, SIG_IGN);

	progname = basename(argv[0]);

	while ((opt = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(0);
		case '?':
		default:
			usage(1);
		}
	}

	if (argc >= optind + 1 && strcmp(argv[1], "-") != 0) {
		in = fopen(argv[1], "rb");
		if (in == NULL) {
			log_err("Failed to open %s: %s", argv[1], strerror(errno));
			rc = -1;
			goto exit;
		}
	} else {
		in = stdin;
	}

	if (argc >= optind + 2 && strcmp(argv[2], "-") != 0) {
		outfd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
		if (outfd == -1) {
			log_err("Failed to open %s: %s", argv[2], strerror(errno));
			rc = -1;
			goto exit;
		}

		out = fdopen(outfd, "w");
		if (out == NULL) {
			log_err("Failed to open %s: %s", argv[2], strerror(errno));
			rc = -1;
			goto exit;
		}
	} else {
		out = stdout;
	}
	out_file = out;

	if (argc >= optind + 3) {
		log_err("Too many arguments");
		usage(1);
	}

	rc = ppfile_to_module_package(in, &mod_pkg);
	if (rc != 0) {
		goto exit;
	}
	fclose(in);
	in = NULL;

	rc = module_package_to_cil(mod_pkg);
	if (rc != 0) {
		goto exit;
	}

exit:
	if (in != NULL) {
		fclose(in);
	}
	if (out != NULL) {
		fclose(out);
	}
	if (outfd != -1) {
		close(outfd);
		if (rc != 0) {
			unlink(argv[2]);
		}
	}
	sepol_module_package_free(mod_pkg);

	return rc;
}
