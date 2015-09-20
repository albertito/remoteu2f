// pam_prompt_exec is a PAM module which calls an external command, which
// prompts the user for input.
//
// It is analogous to pam_exec(8), but allows the program to print a prompt
// (by writing to stdout) and then reading input back (by reading from stdin).
// The command is run as the PAM user.

// We use features from POSIX 2008.
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

// Buffer size to use when reading stdout.
// Note this is the maximum size we read, 4k should be plenty for our
// interactive use.
static const int BUFSIZE = 4 * 1024;

// The exit status of the child if we have to exit before exec()ing.
// Nothing special about 217, it's just easy to find.
static const int CHILD_ERROR = 217;

// Send text to PAM, get a response back.
static struct pam_response *pam_talk(pam_handle_t *pamh, char *text)
{
	int rv;
	struct pam_conv *conv;
	rv = pam_get_item(pamh, PAM_CONV, (void *)&conv);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_item() failed: %d", rv);
		return NULL;
	}

	const struct pam_message msg = {
	    .msg_style = PAM_PROMPT_ECHO_ON, .msg = text,
	};
	const struct pam_message *pmsg = &msg;

	struct pam_response *resp = NULL;
	rv = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "conv->conv() failed: %d", rv);
		return NULL;
	}

	return resp;
}

// Move the given fd to an fd >= 3; exit if it fails.
static int move_to_high_fd(pam_handle_t *pamh, int fd)
{
	while (fd < 3) {
		fd = dup(fd);
		if (fd < 0) {
			pam_syslog(pamh, LOG_ERR, "dup() failed: %s",
				   strerror(errno));
			_exit(CHILD_ERROR);
		}
	}

	return fd;
}

// Build a "NAME=VALUE" string to use in the environment list.
static char *build_env_value(pam_handle_t *pamh, const char *name,
			     const char *value)
{
	// We'll return "name=value\0"
	// 3 extra bytes to account for the =, \0 and one more just to be
	// extra cautious.
	size_t bsize = strlen(name) + strlen(value) + 3;
	char *buf = calloc(bsize, 1);
	if (buf == NULL) {
		pam_syslog(pamh, LOG_ERR, "calloc(env item) failed: %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}
	snprintf(buf, bsize, "%s=%s", name, value);
	return buf;
}

// Build the environment for the child, or die trying.
static char **build_child_env(pam_handle_t *pamh, const char *pam_type)
{
	char **env = pam_getenvlist(pamh);
	if (env == NULL) {
		pam_syslog(pamh, LOG_ERR, "pam_getenvlist() failed: %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}

	// Find how many elements are in env.
	int envlen = 0;
	for (envlen = 0; env[envlen] != NULL; envlen++)
		;

	// Variables to copy.
	struct {
		int item;
		const char *name;
	} items[] = {
	    {PAM_SERVICE, "PAM_SERVICE"}, {PAM_USER, "PAM_USER"},
	    {PAM_TTY, "PAM_TTY"},	 {PAM_RHOST, "PAM_RHOST"},
	    {PAM_RUSER, "PAM_RUSER"},
	};
	const int nitems = 5;

	// Realloc to account for nitems + PAM_TYPE (below) + NULL.
	env = realloc(env, (envlen + nitems + 2) * sizeof(char *));
	if (env == NULL) {
		pam_syslog(pamh, LOG_ERR, "realloc() failed: %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}

	// Add the items to the environment.
	for (int i = 0; i < nitems; i++) {
		const void *item;

		// Skip items that are not found.
		if (pam_get_item(pamh, items[i].item, &item) != PAM_SUCCESS ||
		    item == NULL) {
			continue;
		}

		// Add it to the environment.
		env[envlen] =
		    build_env_value(pamh, items[i].name, (const char *)item);
		envlen++;
		env[envlen] = NULL;
	}

	// And PAM_TYPE to the type we know.
	env[envlen] = build_env_value(pamh, "PAM_TYPE", pam_type);
	envlen++;
	env[envlen] = NULL;

	return env;
}

// Drop privileges to the user we are validating.
// PAM modules usually (but not always) run as root, this will drop privileges
// to that user.
// It is only called during the child process initialization.
static void drop_privileges(pam_handle_t *pamh)
{
	// Get the user information.
	const char *user = NULL;
	int rv = pam_get_user(pamh, &user, NULL);
	if (rv != PAM_SUCCESS || user == NULL) {
		pam_syslog(pamh, LOG_ERR, "could not get PAM user: %d", rv);
		_exit(CHILD_ERROR);
	}

	struct passwd *pwd = getpwnam(user);
	if (pwd == NULL) {
		pam_syslog(pamh, LOG_ERR, "could not get user info: %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}

	// Change the group.
	uid_t old_gid = getegid();
	if (old_gid != pwd->pw_gid && setegid(pwd->pw_gid)) {
		pam_syslog(pamh, LOG_ERR, "error in setegid(): %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}

	// Change the user.
	uid_t old_uid = geteuid();
	if (old_uid != pwd->pw_uid && seteuid(pwd->pw_uid)) {
		pam_syslog(pamh, LOG_ERR, "error in seteuid(): %s",
			   strerror(errno));
		_exit(CHILD_ERROR);
	}
}

// Like read() but either fails or returns a complete read.
static ssize_t full_read(int fd, void *buf, size_t count)
{
	ssize_t rv;
	size_t c = 0;

	while (c < count) {
		rv = read(fd, (char *)buf + c, count - c);
		if (rv < 0) {
			return rv;
		} else if (rv == 0) {
			return c;
		}

		c += rv;
	}

	return count;
}

// Like write() but either fails or returns a complete write.
static ssize_t full_write(int fd, const void *buf, size_t count)
{
	ssize_t rv;
	size_t c = 0;

	while (c < count) {
		rv = write(fd, (char *)buf + c, count - c);
		if (rv < 0)
			return rv;

		c += rv;
	}

	return count;
}

static int prompt_exec(const char *pam_type, pam_handle_t *pamh, int argc,
		       const char **argv)
{
	int binary_path_pos = -1;
	for (int i = 0; i < argc; i++) {
		// Stop if we got to the binary path.
		if (argv[i][0] == '/') {
			binary_path_pos = i;
			break;
		}

		if (strncmp(argv[i], "type=", 5) == 0) {
			// Ignore if we are not invoked with the expected
			// pam type.
			if (strcmp(pam_type, &argv[i][5]) != 0) {
				return PAM_IGNORE;
			}
		}
	}

	if (binary_path_pos == -1) {
		pam_syslog(pamh, LOG_ERR, "No program to exec");
		return PAM_SERVICE_ERR;
	}

	// Set up stdin pipe.
	int stdin_fds[2] = {-1, -1};
	if (pipe(stdin_fds) != 0) {
		pam_syslog(pamh, LOG_ERR, "Could not create stdin pipe: %s",
			   strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	// Set up stdout pipe.
	int stdout_fds[2] = {-1, -1};
	if (pipe(stdout_fds) != 0) {
		pam_syslog(pamh, LOG_ERR, "Could not create stdout pipe: %s",
			   strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	pid_t pid = fork();
	if (pid == -1) {
		pam_syslog(pamh, LOG_ERR, "Could not fork(): %s",
			   strerror(errno));
		return PAM_SYSTEM_ERR;
	} else if (pid > 0) { // Parent.
		// Close the fds we don't use.
		close(stdin_fds[0]);
		close(stdout_fds[1]);

		// Read the prompt from stdout.
		char buf[BUFSIZE];
		int buflen = -1;
		memset(buf, 0, BUFSIZE);

		buflen = full_read(stdout_fds[0], buf, BUFSIZE - 1);
		if (buflen < 0) {
			pam_syslog(pamh, LOG_ERR, "Could not from stdout: %s",
				   strerror(errno));
			return PAM_SYSTEM_ERR;
		}
		close(stdout_fds[0]);

		// Talk to the user, but only if there's a prompt.
		if (buflen > 0) {
			// Converse via PAM.
			struct pam_response *response = pam_talk(pamh, buf);
			if (response == NULL) {
				return PAM_SYSTEM_ERR;
			}

			// Send response back via stdin.
			int rlen = strlen(response->resp);
			int rv = full_write(stdin_fds[1], response->resp, rlen);
			if (rv != rlen) {
				// Note this is just informational: the child
				// may not care about this and may have even
				// closed it.
				pam_syslog(pamh, LOG_NOTICE,
					   "Could not write to stdin: %s",
					   strerror(errno));
			}

			close(stdin_fds[1]);

			free(response->resp);
			free(response);
		}

		// Wait for the program to die.
		pid_t rv;
		int status = 0;
		while ((rv = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
			;
		if (rv != pid) {
			pam_syslog(pamh, LOG_ERR, "waitpid() failed: %s",
				   strerror(errno));
			return PAM_SYSTEM_ERR;
		}

		const char *binary = argv[binary_path_pos];

		if (status == 0) {
			return PAM_SUCCESS;
		} else if (WIFEXITED(status)) {
			pam_error(pamh, "%s failed, exit code: %d", binary,
				  WEXITSTATUS(status));
			return PAM_SYSTEM_ERR;
		} else if (WIFSIGNALED(status)) {
			pam_error(pamh, "%s failed, signal: %d", binary,
				  WTERMSIG(status));
			return PAM_SYSTEM_ERR;
		} else {
			pam_error(pamh, "%s failed, unknown status: 0x%x",
				  binary, status);
			return PAM_SYSTEM_ERR;
		}
	} else { // Child.
		// Close the fds we don't use.
		close(stdin_fds[1]);
		close(stdout_fds[0]);

		// Move stdin and stdout pipes to high file descriptors, so we
		// can dup() them safely later.
		int stdin_fd = move_to_high_fd(pamh, stdin_fds[0]);
		int stdout_fd = move_to_high_fd(pamh, stdout_fds[1]);

		// Now move stdin and stdout to the canonical fds.
		if (dup2(stdin_fd, STDIN_FILENO) == -1) {
			pam_syslog(pamh, LOG_ERR, "dup2(stdin) failed: %s",
				   strerror(errno));
			_exit(CHILD_ERROR);
		}
		if (dup2(stdout_fd, STDOUT_FILENO) == -1) {
			pam_syslog(pamh, LOG_ERR, "dup2(stdout) failed: %s",
				   strerror(errno));
			_exit(CHILD_ERROR);
		}

		// Close unused fds, just in case.
		for (int i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			close(i);
		}

		// Run in a new session, just in case.
		if (setsid() == -1) {
			pam_syslog(pamh, LOG_ERR, "setsid() failed: %s",
				   strerror(errno));
			_exit(CHILD_ERROR);
		}

		// Drop privileges by changing to the new user.
		drop_privileges(pamh);

		// Set up the environment, with the PAM environment + the
		// variables with the PAM information to pass on.
		char **child_env = build_child_env(pamh, pam_type);

		// Set up the child's argv.
		int child_argc = argc - binary_path_pos + 2;
		char **child_argv = calloc(child_argc, sizeof(char *));
		if (child_argv == NULL) {
			pam_syslog(pamh, LOG_ERR, "calloc(argc) failed: %s",
				   strerror(errno));
			_exit(CHILD_ERROR);
		}

		int i, j;
		for (i = binary_path_pos, j = 0; i < argc; i++, j++) {
			child_argv[j] = strdup(argv[i]);
		}
		child_argv[j] = NULL;

		// Exec!
		execve(child_argv[0], child_argv, child_env);
		pam_syslog(pamh, LOG_ERR, "execve(%s) failed: %s",
			   strerror(errno), child_argv[0]);
		_exit(CHILD_ERROR);
	}
}

/*
 * PAM functions for auth, session and account.
 */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	return prompt_exec("auth", pamh, argc, argv);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	if (flags & PAM_PRELIM_CHECK)
		return PAM_SUCCESS;
	return prompt_exec("password", pamh, argc, argv);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return prompt_exec("account", pamh, argc, argv);
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
	return prompt_exec("open_session", pamh, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
			 const char **argv)
{
	return prompt_exec("close_session", pamh, argc, argv);
}
