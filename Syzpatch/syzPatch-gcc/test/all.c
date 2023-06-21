#include <stdio.h>
#include <stdlib.h>

struct test_struct {
	int aaaa;
	int pad;
	char *b;
	int c;
};

struct common {
    struct test_struct t;
    struct test_struct *tt;
};

#define notrace         __attribute__((__no_instrument_function__))
static notrace void  __sanitizer_obj_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_enable_trace(unsigned long a, unsigned long b) {}
static notrace void  __sanitizer_cov_trace_int8(unsigned long a, unsigned long b) {}
static notrace void  __sanitizer_cov_pre_trace(int a) {}
static notrace void  __sanitizer_cov_post_trace(int a) {}

int main() {
	struct common c;
    c.tt = malloc(100);
	struct test_struct tt;
	read(0, c.t, sizeof (c.t));
	read(0, c.tt, 100);
	if (c.t.aaaa > 10) {
		c.t.aaaa = 10;
	}
	
	if (c.tt->c > 111)
		c.tt->c = 111;
	c.tt->aaaa = c.tt->c;
	read(0, c.tt->b, 100);
	printf("t b %s\n", c.tt->b);
}
