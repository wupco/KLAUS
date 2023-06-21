struct test {
	int a;
	char *b;
	int c;
};

#define notrace         __attribute__((__no_instrument_function__))

static notrace void __sanitizer_obj_cov_trace_pc(void) {}
static notrace void  __sanitizer_cov_trace_pc(void) {}
int main() {
	struct test t;
	printf("%d  %x %d", t.a, t.b, t.c);
	read(0, &t, 18);
	int c = t.a;
	char *xx = t.b;

	printf("%d %x\n", c, xx);
}
