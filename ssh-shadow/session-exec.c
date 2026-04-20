#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void die(const char *msg) {
  fprintf(stderr, "[ssh-shadow] session-exec error: %s: %s\n", msg, strerror(errno));
  exit(127);
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <workspace> <login_user> <cmd> [args...]\n", argv[0]);
    return 127;
  }

  const char *workspace = argv[1];
  const char *login_user = argv[2];
  char **cmd_argv = &argv[3];

  struct stat st;
  if (stat(workspace, &st) != 0 || !S_ISDIR(st.st_mode)) {
    errno = ENOENT;
    die("workspace is not a directory");
  }

  struct passwd *pw = getpwnam(login_user);
  if (!pw) {
    errno = ENOENT;
    die("unknown login user");
  }

  if (chdir(workspace) != 0) {
    die("chdir(workspace)");
  }
  if (chroot(".") != 0) {
    die("chroot(workspace)");
  }

  char home_in_chroot[512];
  snprintf(home_in_chroot, sizeof(home_in_chroot), "/home/%s", login_user);
  if (chdir(home_in_chroot) != 0) {
    if (chdir("/") != 0) {
      die("chdir(/)");
    }
  }

  if (setenv("SSH_SHADOW_SANDBOX", "1", 1) != 0) die("setenv SSH_SHADOW_SANDBOX");
  if (setenv("HOME", home_in_chroot, 1) != 0) die("setenv HOME");
  if (setenv("USER", login_user, 1) != 0) die("setenv USER");
  if (setenv("LOGNAME", login_user, 1) != 0) die("setenv LOGNAME");
  if (setenv("PATH", "/opt/ssh-shadow/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1) != 0) {
    die("setenv PATH");
  }

  if (initgroups(login_user, pw->pw_gid) != 0) {
    die("initgroups");
  }
  if (setgid(pw->pw_gid) != 0) {
    die("setgid");
  }
  if (setuid(pw->pw_uid) != 0) {
    die("setuid");
  }

  execvp(cmd_argv[0], cmd_argv);
  die("execvp");
  return 127;
}
