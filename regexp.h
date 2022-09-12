/*
 * small regex library for C/C++
 * https://github.com/deinernstjetzt/mregexp
 */
#ifndef _REGEXP_H
#define _REGEXP_H

#include <cstring>
#include <csetjmp>
#include <cstdarg>
#include <limits>

#ifndef UINT_MAX
#define UINT_MAX std::numeric_limits<unsigned int>::max()
#endif

typedef struct {
	size_t match_begin;
	size_t match_end;
} RegexpMatch;

typedef enum {
	REGEXP_OK = 0,
	REGEXP_FAILED_ALLOC,
	REGEXP_INVALID_UTF8,
	REGEXP_INVALID_PARAMS,
	REGEXP_EARLY_QUANTIFIER,
	REGEXP_INVALID_COMPLEX_QUANT,
	REGEXP_UNEXPECTED_EOL,
	REGEXP_INVALID_COMPLEX_CLASS,
	REGEXP_UNCLOSED_SUBEXPRESSION,
} RegexpError;

namespace {
    static inline unsigned utf8_char_width(uint8_t c) {
        int a1 = !(128 & c) && 1;
        int a2 = (128 & c) && (64 & c) && !(32 & c);
        int a3 = (128 & c) && (64 & c) && (32 & c) && !(16 & c);
        int a4 = (128 & c) && (64 & c) && (32 & c) && (16 & c) && !(8 & c);
        return a1 * 1 + a2 * 2 + a3 * 3 + a4 * 4;
    }

    static inline bool utf8_valid(const char *s) {
        const size_t len = strlen(s);
        for (size_t i = 0; i < len;) {
            const unsigned width = utf8_char_width((uint8_t)s[i]);
            if (width == 0) return false;
            if (i + width > len) return false;
            for (unsigned j = 1; j < width; ++j) {
                if ((s[i + j] & (128 + 64)) != 128) return false;
            }
            i += width;
        }
        return true;
    }
    static const int utf8_peek_mods[] = {0, 127, 31, 15, 7};
    static inline uint32_t utf8_peek(const char *s) {
        if (*s == 0) return 0;
        const unsigned width = utf8_char_width((uint8_t)s[0]);
        size_t ret = 0;
        ret = s[0] & utf8_peek_mods[width];
        for (unsigned i = 1; i < width; ++i) {
            ret <<= 6;
            ret += s[i] & 63;
        }
        return ret;
    }

    static inline const char *utf8_next(const char *s) {
        if (*s == 0) return nullptr;
        const unsigned width = utf8_char_width((uint8_t)s[0]);
        return s + width;
    }
    union RegexNode;
    typedef bool (*MatchFunc)(union RegexNode *node, const char *orig, const char *cur, const char **next);
    typedef struct GenericNode {
        union RegexNode *prev;
        union RegexNode *next;
        MatchFunc match;
    } GenericNode;
    typedef struct {
        GenericNode generic;
        uint32_t chr;
    } CharNode;
    typedef struct {
        GenericNode generic;
        union RegexNode *subexp;
        size_t min, max;
    } QuantNode;

    typedef struct {
        GenericNode generic;
        uint32_t first, last;
    } RangeNode;

    typedef struct {
        GenericNode generic;
        RangeNode *ranges;
        bool negate;
    } ClassNode;

    typedef struct {
        GenericNode generic;
        union RegexNode *subexp;
        RegexpMatch cap;
    } CapNode;

    typedef struct {
        GenericNode generic;
        union RegexNode *left;
        union RegexNode *right;
    } OrNode;

    typedef union RegexNode {
        GenericNode generic;
        CharNode chr;
        QuantNode quant;
        ClassNode cls;
        RangeNode range;
        CapNode cap;
        OrNode or_;
    } RegexNode;
    static bool is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        if (node == nullptr) {
            *next = cur;
            return true;
        }
        return ((node->generic.match)(node, orig, cur, next)) && is_match(node->generic.next, orig, *next, next);
    }
    static bool char_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        if (*cur == 0) return false;
        *next = utf8_next(cur);
        return node->chr.chr == utf8_peek(cur);
    }
    static bool start_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        *next = cur;
        return true;
    }
    static bool anchor_begin_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        *next = cur;
        return strlen(orig) == strlen(cur);
    }
    static bool anchor_end_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        *next = cur;
        return strlen(cur) == 0;
    }
    static bool any_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        if (*cur) {
            *next = utf8_next(cur);
            return true;
        }
        return false;
    }
    static bool quant_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        QuantNode *quant = (QuantNode *)node;
        size_t matches = 0;
        while (is_match(quant->subexp, orig, cur, next)) {
            matches++;
            cur = *next;
            if (matches >= quant->max) break;
        }
        *next = cur;
        return matches >= quant->min;
    }
    static bool class_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        ClassNode *cls = (ClassNode *)node;
        if (*cur == 0) return false;
        const uint32_t chr = utf8_peek(cur);
        *next = utf8_next(cur);
        bool found = false;
        for (RangeNode *range = cls->ranges; range != NULL; range = (RangeNode *)range->generic.next) {
            if (chr >= range->first && chr <= range->last) {
                found = true;
                break;
            }
        }
        if (cls->negate) {
            found = !found;
        }
        return found;
    }
    static bool cap_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        CapNode *cap = (CapNode *)node;
        if (is_match(cap->subexp, orig, cur, next)) {
            cap->cap.match_begin = cur - orig;
            cap->cap.match_end = (*next) - orig;
            return true;
        }
        return false;
    }
    static bool or_is_match(RegexNode *node, const char *orig, const char *cur, const char **next) {
        OrNode *or_ = (OrNode *)node;
        if (or_->generic.next != nullptr) {
            or_->right = or_->generic.next;
            or_->generic.next = nullptr;
        }
        if (is_match(or_->left, orig, cur, next) && or_->left != nullptr) {
            return true;
        }
        return is_match(or_->right, orig, cur, next) && or_->right != nullptr;
    }
    struct {
        RegexpError err;
        const char *s;
        jmp_buf buf;
    } CompileException;

    static inline void clear_compile_exception(void) {
        CompileException.err = REGEXP_OK;
        CompileException.s = NULL;
    }
    static void throw_compile_exception(RegexpError err, const char *s) {
        CompileException.err = err;
        CompileException.s = s;
        longjmp(CompileException.buf, 1);
    }
    static size_t calc_compiled_escaped_len(const char *s, const char **leftover) {
        if (*s == 0) {
            throw_compile_exception(REGEXP_UNEXPECTED_EOL, s);
        }
        const uint32_t chr = utf8_peek(s);
        *leftover = utf8_next(s);
        switch (chr) {
            case 's': case 'S': case 'w': case 'W': return 5;
            case 'd': case 'D': return 2;
        }
        return 1;
    }
    static const size_t calc_compiled_class_len(const char *s, const char **leftover) {
        if (*s == '^') s++;
        size_t ret = 1;
        while (*s && *s != ']') {
            uint32_t chr = utf8_peek(s);
            s = utf8_next(s);
            if (chr == '\\') {
                s = utf8_next(s);
            }
            if (*s == '-' && s[1] != ']') {
                s++;
                chr = utf8_peek(s);
                s = utf8_next(s);
                if (chr == '\\') s = utf8_next(s);
            }
            ret++;
        }
        if (*s == ']') {
            s++;
            *leftover = s;
        } else {
            throw_compile_exception(REGEXP_INVALID_COMPLEX_CLASS, s);
        }
        return ret;
    }
    static const size_t calc_compiled_len(const char *s) {
        if (*s == 0) return 1;
        const uint32_t chr = utf8_peek(s);
        size_t ret = 0;
        s = utf8_next(s);
        switch (chr) {
            case '{': {
                const char *end = strstr(s, "}");
                if (end == nullptr) {
                    throw_compile_exception(REGEXP_INVALID_COMPLEX_QUANT, s);
                }
                s = end + 1;
                ret = 1;
            } break;
            case '\\': {
                ret = calc_compiled_escaped_len(s, &s);
            } break;
            case '[': {
                ret = calc_compiled_class_len(s, &s);
            } break;
            default: {
                ret = 1;
            } break;
        }
        return ret + calc_compiled_len(s);
    }
    static void append_quant(RegexNode **prev, RegexNode *cur, unsigned int min, unsigned int max, const char *re) {
        cur->generic.match = quant_is_match;
        cur->generic.next = nullptr;
        cur->generic.prev = nullptr;

        cur->quant.max = max;
        cur->quant.min = min;
        cur->quant.subexp = *prev;

        *prev = (*prev)->generic.prev;
        if (*prev == nullptr) {
            throw_compile_exception(REGEXP_EARLY_QUANTIFIER, re);
        }
        cur->quant.subexp->generic.next = nullptr;
        cur->quant.subexp->generic.prev = nullptr;
    }
    static inline bool is_digit(uint32_t c) {
        return c >= '0' && c <= '9';
    }
    static inline size_t parse_digit(const char *s, const char **leftover) {
        size_t ret = 0;
        while (*s) {
            uint32_t chr = utf8_peek(s);
            if (is_digit(chr)) {
                ret *= 10;
                ret += chr - '0';
                s = utf8_next(s);
            } else {
                break;
            }
        }
        *leftover = s;
        return ret;
    }
    static void parse_complex_quant(const char *re, const char **leftover, size_t *min_p, size_t *max_p) {
        if (*re == 0) {
            throw_compile_exception(REGEXP_INVALID_COMPLEX_QUANT, re);
        }
        uint32_t tmp = utf8_peek(re);
        size_t min = 0, max = UINT_MAX;
        if (is_digit(tmp)) {
            min = parse_digit(re, &re);
        } else if (tmp != ',') {
            throw_compile_exception(REGEXP_INVALID_COMPLEX_QUANT, re);
        }
        tmp = utf8_peek(re);
        if (tmp == ',') {
            re = utf8_next(re);
            if (is_digit(utf8_peek(re))) {
                max = parse_digit(re, &re);
            } else {
                max = UINT_MAX;
            }
        } else {
            max = min;
        }
        tmp = utf8_peek(re);
        if (tmp == '}') {
            *leftover = re + 1;
            *min_p = min;
            *max_p = max;
        } else {
            throw_compile_exception(REGEXP_INVALID_COMPLEX_QUANT, re);
        }
    }
    static RegexNode *append_class(RegexNode *cur, bool negate, size_t n, ...) {
        cur->cls.negate = negate;
        cur->cls.ranges = (RangeNode *)(n ? cur + 1 : NULL);
        cur->generic.match = class_is_match;
        cur->generic.next = nullptr;
        cur->generic.prev = nullptr;

        va_list ap;
        va_start(ap, n);
        RegexNode *prev = nullptr;
        cur = cur + 1;

        for (unsigned int i = 0; i < n; ++i) {
            const uint32_t first = va_arg(ap, uint32_t);
            const uint32_t last = va_arg(ap, uint32_t);

            cur->generic.next = nullptr;
            cur->generic.prev = prev;

            if (prev)
                prev->generic.next = cur;

            cur->range.first = first;
            cur->range.last = last;

            prev = cur;
            cur = cur + 1;
        }

        va_end(ap);

        return cur;
    }
    static RegexNode *compile_next_escaped(const char *re, const char **leftover, RegexNode *cur) {
        if (*re == 0) {
            throw_compile_exception(REGEXP_UNEXPECTED_EOL, re);
        }
        const uint32_t chr = utf8_peek(re);
        *leftover = utf8_next(re);
        RegexNode *ret = cur + 1;
        switch (chr) {
            case 'n': {
                cur->chr.chr = '\n';
                cur->generic.match = char_is_match;
            } break;
            case 't': {
                cur->chr.chr = '\t';
                cur->generic.match = char_is_match;
            } break;
            case 'r': {
                cur->chr.chr = '\r';
                cur->generic.match = char_is_match;
            } break;
            case 's': {
                ret = append_class(cur, false, 4, ' ', ' ', '\t', '\t', '\r', '\r', '\n', '\n');
            } break;
            case 'S': {
                ret = append_class(cur, true, 4, ' ', ' ', '\t', '\t', '\r', '\r', '\n', '\n');
            } break;
            case 'w': {
                ret = append_class(cur, false, 4, 'a', 'z', 'A', 'Z', '0', '9', '_', '_');
            } break;
            case 'W': {
                ret = append_class(cur, true, 4, 'a', 'z', 'A', 'Z', '0', '9', '_', '_');
            } break;
            case 'd': {
                ret = append_class(cur, false, 1, '0', '9');
            } break;
            case 'D': {
                ret = append_class(cur, true, 1, '0', '9');
            } break;
            default: {
                cur->chr.chr = chr;
                cur->generic.match = char_is_match;
            } break;
        }
        return ret;
    }
    static RegexNode *compile_next_complex_class(const char *re, const char **leftover, RegexNode *cur) {
        cur->generic.match = class_is_match;
        cur->generic.next = nullptr;
        cur->generic.prev = nullptr;
        if (*re == '^') {
            re++;
            cur->cls.negate = true;
        } else {
            cur->cls.negate = false;
        }
        cur->cls.ranges = nullptr;
        cur = cur + 1;
        RegexNode *prev = nullptr;
        while (*re && *re != ']') {
            uint32_t first = 0, last = 0;
            first = utf8_peek(re);
            re = utf8_next(re);
            if (first == '\\') {
                if (*re == 0) {
                    throw_compile_exception(REGEXP_INVALID_COMPLEX_CLASS, re);
                }
                first = utf8_peek(re);
                re = utf8_next(re);
            }
            if (*re == '-' && re[1] != ']' && re[1]) {
                re++;
                last = utf8_peek(re);
                re = utf8_next(re);
                if (last == '\\') {
                    if (*re == 0) {
                        throw_compile_exception(REGEXP_INVALID_COMPLEX_CLASS,re);
                    }
                    last = utf8_peek(re);
                    re = utf8_next(re);
                }
            } else {
                last = first;
            }
            cur->range.first = first;
            cur->range.last = last;
            cur->generic.prev = prev;
            cur->generic.next = nullptr;
            if (prev == nullptr) {
                (cur - 1)->cls.ranges = (RangeNode *)cur;
            } else {
                prev->generic.next = cur;
            }

            prev = cur;
            cur++;
        }
        if (*re == ']') {
            *leftover = re + 1;
            return cur;
        } else {
            throw_compile_exception(REGEXP_INVALID_COMPLEX_CLASS, re);
            return nullptr; // Unreachable
        }
    }
    static const char *find_closing_par(const char *s) {
        size_t level = 1;
        for (; *s && level != 0; ++s) {
            if (*s == '\\') {
                s++;
            } else if (*s == '(') {
                level++;
            } else if (*s == ')') {
                level--;
            }
        }
        if (level == 0) {
            return s;
        }
        return nullptr;
    }
    static RegexNode *compile(const char *re, const char *end, RegexNode *nodes);
    static RegexNode *compile_next_cap(const char *re, const char **leftover,RegexNode *cur) {
        cur->cap.cap.match_begin = 0;
        cur->cap.cap.match_end = 0;
        cur->cap.subexp = cur + 1;
        cur->generic.next = nullptr;
        cur->generic.prev = nullptr;
        cur->generic.match = cap_is_match;

        const char *end = find_closing_par(re);

        if (end == nullptr) {
            throw_compile_exception(REGEXP_UNCLOSED_SUBEXPRESSION, re);
        }
        *leftover = end;
        return compile(re, end - 1, cur + 1);
    }
    static RegexNode *insert_or(RegexNode *cur, RegexNode **prev) {
        cur->generic.match = or_is_match;
        cur->generic.next = nullptr;
        cur->generic.prev = nullptr;

        // Find last start node
        RegexNode *begin = *prev;

        while (begin->generic.match != start_is_match) {
            begin = begin->generic.prev;
        }

        cur->or_.left = begin->generic.next;
        *prev = begin;

        return cur + 1;
    }
    static RegexNode *compile_next(const char *re, const char **leftover, RegexNode *prev, RegexNode *cur) {
        if (*re == 0) return nullptr;
        const uint32_t chr = utf8_peek(re);
        re = utf8_next(re);
        RegexNode *next = cur + 1;

        switch (chr) {
            case '^':
                cur->generic.match = anchor_begin_is_match;
            break;
            case '$':
                cur->generic.match = anchor_end_is_match;
            break;
            case '.':
                cur->generic.match = any_is_match;
            break;
            case '*':
                append_quant(&prev, cur, 0, UINT_MAX, re);
            break;
            case '+':
                append_quant(&prev, cur, 1, UINT_MAX, re);
            break;
            case '?':
                append_quant(&prev, cur, 0, 1, re);
            break;
            case '{': {
                size_t min = 0, max = UINT_MAX;
                const char *leftover = NULL;
                parse_complex_quant(re, &leftover, &min, &max);
                append_quant(&prev, cur, min, max, re);
                re = leftover;
            } break;
            case '[':
                next = compile_next_complex_class(re, &re, cur);
            break;
            case '(':
                next = compile_next_cap(re, &re, cur);
            break;
            case '\\':
                next = compile_next_escaped(re, &re, cur);
            break;
            case '|':
                next = insert_or(cur, &prev);
            break;
            default: {
                cur->chr.chr = chr;
                cur->generic.match = char_is_match;
            } break;
        }

        cur->generic.next = NULL;
        cur->generic.prev = prev;
        prev->generic.next = cur;
        *leftover = re;

        return next;
    }
    static RegexNode *compile(const char *re, const char *end, RegexNode *nodes) {
        RegexNode *prev = nodes;
        RegexNode *cur = nodes + 1;

        prev->generic.next = nullptr;
        prev->generic.prev = nullptr;
        prev->generic.match = start_is_match;

        while (cur != nullptr && re != nullptr && re < end) {
            const char *next = nullptr;
            RegexNode *next_node = compile_next(re, &next, prev, cur);

            prev = cur;
            cur = next_node;
            re = next;
        }

        return cur;
    }
    static size_t cap_node_count(RegexNode *nodes) {
        if (nodes == nullptr) return 0;
        if (nodes->generic.match == quant_is_match) {
            return cap_node_count(nodes->quant.subexp) + cap_node_count(nodes->generic.next);
        }
        if (nodes->generic.match == cap_is_match) {
            return cap_node_count(nodes->quant.subexp) + cap_node_count(nodes->generic.next) + 1;
        }
        return cap_node_count(nodes->generic.next);
    }
    static RegexNode *find_capture_node(RegexNode *node, size_t index) {
        if (node == nullptr) return nullptr;
        if (node->generic.match == cap_is_match) {
            if (index == 0) return node;
            const size_t subexp_len = cap_node_count(node->cap.subexp);
            if (index <= subexp_len) {
                return find_capture_node(node->cap.subexp, index - subexp_len);
            }
            return find_capture_node(node->generic.next, index - 1 - subexp_len);
        }
        if (node->generic.match == quant_is_match) {
            const size_t subexp_len = cap_node_count(node->quant.subexp);
            if (index < subexp_len) {
                return find_capture_node(node->quant.subexp, index);
            }
            return find_capture_node(node->generic.next, index);
        }
        return find_capture_node(node->generic.next, index);
    }
    struct Regexp {
        RegexNode *nodes;
    };
}
typedef struct Regexp Regexp;
bool regexp_valid_utf8(const char *s) {
    return utf8_valid(s);
}
Regexp *regexp_compile(const char *re) {
    clear_compile_exception();
    if (re == nullptr) {
        CompileException.err = REGEXP_INVALID_PARAMS;
        return nullptr;
    }
    if (!utf8_valid(re)) {
        CompileException.err = REGEXP_INVALID_UTF8;
        CompileException.s = nullptr;
        return nullptr;
    }
    Regexp *ret = (Regexp *)calloc(1, sizeof(Regexp));
    if (ret == NULL) {
		CompileException.err = REGEXP_FAILED_ALLOC;
		CompileException.s = nullptr;
		return NULL;
	}

	RegexNode *nodes = nullptr;

	if (setjmp(CompileException.buf)) {
		// Error callback
		free(ret);
		free(nodes);

		return nullptr;
	}

	const size_t compile_len = calc_compiled_len(re);
	nodes = (RegexNode *)calloc(compile_len, sizeof(RegexNode));
	compile(re, re + strlen(re), nodes);
	ret->nodes = nodes;

	return ret;
}
RegexpError regexp_error(void) {
    return CompileException.err;
}
bool regexp_match(Regexp *re, const char *s, RegexpMatch *m) {
    clear_compile_exception();
    if (re == nullptr || s == nullptr || m == nullptr) {
        CompileException.err = REGEXP_INVALID_PARAMS;
        return false;
    }
    m->match_begin = UINT_MAX;
	m->match_end = UINT_MAX;
    for (const char *tmp_s = s; *tmp_s; tmp_s = utf8_next(tmp_s)) {
		const char *next = nullptr;
		if (is_match(re->nodes, s, tmp_s, &next)) {
			m->match_begin = tmp_s - s;
			m->match_end = next - s;
			return true;
		}
	}

	return false;
}
RegexpMatch *regexp_all_matches(Regexp *re, const char *s, size_t *sz) {
    RegexpMatch *matches = nullptr;
	size_t offset = 0;
	*sz = 0;

	const char *end = s + strlen(s);
	while (s < end) {
		RegexpMatch tmp;
		if (regexp_match(re, s, &tmp)) {
			size_t end = tmp.match_end;
			s = s + end;

			matches = (RegexpMatch *)realloc(matches, (++(*sz)) * sizeof(RegexpMatch));

			if (matches == nullptr)
				return nullptr;

			tmp.match_begin += offset;
			tmp.match_end += offset;

			offset += end;
			matches[(*sz) - 1] = tmp;
		} else {
			break;
		}
	}

	return matches;
}
size_t regexp_captures_len(Regexp *re) {
    return cap_node_count(re->nodes);
}
const RegexpMatch *regexp_capture(Regexp *re, size_t index) {
    CapNode *cap = (CapNode *)find_capture_node(re->nodes, index);
    if (cap == nullptr) return nullptr;
    return &cap->cap;
}
void regexp_free(Regexp *re) {
    if (re == nullptr) {
		CompileException.err = REGEXP_INVALID_PARAMS;
		return;
	}
	free(re->nodes);
	free(re);
}
#endif
