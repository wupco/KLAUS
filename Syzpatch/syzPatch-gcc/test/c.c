struct test_struct {
	int aaaa;
	char *b;
	int c;
};

struct common {
    struct test_struct t;
    struct test_struct *tt;
};

#define notrace         __attribute__((__no_instrument_function__))

static notrace void __sanitizer_obj_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_trace_pc(void) {}

int main() {
	struct common c;
    	c.tt = malloc(100);
	struct test_struct tt;
	read(0, c.tt, 100);
	c.t.aaaa = 10;
	printf("t a : %d\n", c.t.aaaa);
	printf("t c : %d\n", c.tt->c);
	c.tt->c = 111;
	read(0, c.tt->b, 100);
	printf("t b %s\n", c.tt->b);
}
