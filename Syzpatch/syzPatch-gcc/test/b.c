struct test_struct {
	int aaaa;
	char *b;
	int c;
};

#define notrace         __attribute__((__no_instrument_function__))

static notrace void __sanitizer_obj_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_enable_trace(unsigned long a, unsigned long b) {}
static notrace void  __sanitizer_cov_trace_int8(unsigned long a, unsigned long b) {}
int main() {
	struct test_struct *t = malloc(100);
	struct test_struct tt;
	read(0, t, 100);
	tt.aaaa = 10;
	printf("t a : %d\n", tt.aaaa);
	printf("t c : %d\n", t->c);
	t->c = 111;
	read(0, t->b, 100);
	printf("t b %s\n", t->b);
}
