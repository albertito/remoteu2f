
all: pam_prompt_exec.so

pam_prompt_exec.so: pam_prompt_exec.c
	$(CC) $(CFLAGS) -std=c11 -Wall -fPIC -shared -lpam $< -o $@


# This is just for convenience during development.
# Unfortunately most distributions don't include a general binary and we have
# to pick a version.
fmt:
	clang-format-3.7 -i pam_prompt_exec.c

clean:
	rm -f pam_prompt_exec.so

.PHONY: all fmt clean
