/*
 * chrlogin.c  -- chroot login
 * acts as login shell in /etc/passwd for a user who has to completely
 * live in a chroot environment
 *
 * Harald Weidner <hweidner@gmx.net>
 * First release: 1999-06-30
 * Last update: 2002-09-01
 *
 * Installation:
 * compile:  gcc -Wall -O2 -s chrlogin.c -o chrlogin
 * install:  cp to /usr/local/sbin, chown root, chmod 4755
 * create chroot directory (here: /home/chroot)
 * create base file system under /home/chroot
 * DISABLE all setuid root binaries under /home/chroot !!!
 *
 * Install a user:
 * create a user using 'adduser'; set password with 'passwd'
 * set /usr/local/sbin/chrlogin als login shell for that user in /etc/passwd
 * create a user in the chroot-Environment
 * (e.g. by filling out /home/chroot/etc/passwd and creating
 * /home/chroot/home/<username> by hand; that user should have the same
 * uid and gid as in /etc/passwd; login shell must be /bin/bash)
 *
 * This code is released under the terms of the GNU General Public
 * License (GPL). THERE IS NO WARRANTY! USE AT YOUR OWN RISK!
 * See http://www.fsf.org/licenses/gpl.html for the full text of the GPL.
 */


/* ----- Configuration parameters ---------------------------------------- */

/* shell for chroot'ed users */

#define SHELL "/bin/bash"

/* chroot directory level
 * This parameter defines, how many subdirs, beginning from the
 * root directory /, are treated as the root of the chroot environment.
 * Example:
 * with CHROOT_LEVEL of 2, /home/chroot/home/joe means:
 *                         0    1      2    3
 * /home/chroot is the chroot base directory,
 * /home/joe is the home directory within the chroot environment
 */
#define CHROOT_LEVEL 2

/* ----- End of configuration parameters --------------------------------- */



#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_STRING 1024


int main(int argc, char *argv[], char *envp[])
{
  int real_user = getuid();
  struct passwd *pw_ent = NULL;
  struct stat stat_buf;
  char *p;
  int cnt;
  char home_dir[MAX_STRING], shell[MAX_STRING], chroot_dir[MAX_STRING];


  /* sanity checks */

  if(geteuid() != 0) {
    fprintf(stderr, "%s: This program needs to be setuid root.\n",
       argv[0]);
    exit(-1);
  }

  if(real_user == 0) {
    fprintf(stderr, "%s: The target user must not be root.\n",
       argv[0]);
    exit(-1);
  }


  /* look up user in system's /etc/passwd */

  if((pw_ent = getpwuid(real_user)) == NULL) {
    fprintf(stderr, "%s: User #%d does not exit in /etc/passwd.\n",
       argv[0], real_user);
    exit(-1);
  }


  /* check home directory */

  strncpy(chroot_dir, pw_ent->pw_dir, MAX_STRING - 1);
  chroot_dir[MAX_STRING] = 0;

  if(chroot_dir[0] != '/') {
    fprintf(stderr, "%s: Home directory %s does not begin with '/'.\n",
       argv[0], chroot_dir);
  }

  if(stat(chroot_dir, &stat_buf) != 0) {
    fprintf(stderr, "%s: Home directory %s does not exist:\n%s\n",
       argv[0], chroot_dir, strerror(errno));
  }


  /* extract chroot directory */

  for(p = chroot_dir, cnt = -1 ; *p; p++) {
    if(*p == '/')
      cnt++;
    if(cnt == CHROOT_LEVEL) {
      *p = 0;
      break;
    }
  }

  if(cnt < CHROOT_LEVEL) {
    fprintf(stderr, "%s: Home directory %s is too short to reach "
       "chroot shell level %d.\n",
       argv[0], chroot_dir, CHROOT_LEVEL);
    exit(-1);
  }


  /* check existance of SHELL */

  strncpy(shell, chroot_dir, MAX_STRING);
  strncat(shell, SHELL, MAX_STRING - strlen(shell));

  if(stat(shell, &stat_buf) != 0) {
    fprintf(stderr, "%s: Could not access login shell %s:\n%s\n",
       argv[0], shell, strerror(errno));
    exit(-1);
  }
  if(!S_ISREG(stat_buf.st_mode)) {
    fprintf(stderr, "%s: Login shell %s must be a regular file.\n",
       argv[0], shell);
    exit(-1);
  }


  /* enter chroot environment */

  if(chdir(chroot_dir) != 0) {
    fprintf(stderr,
       "%s: Could not chdir() to new root directory %s:\n%s\n",
       argv[0], chroot_dir, strerror(errno));
    exit(-1);
  }
  if(chroot(chroot_dir) != 0) {
    fprintf(stderr,
       "%s: Could not chroot() to new root directory %s:\n%s\n",
       argv[0], chroot_dir, strerror(errno));
    exit(-1);
  }
  setuid(real_user);


  /* look up user in chroot's /etc/passwd */

  if((pw_ent = getpwuid(real_user)) == NULL) {
    fprintf(stderr, "%s: Could not find user #%d in chroot's /etc/passwd.\n",
       argv[0], real_user);
    exit(-1);
  }


  /* change to users home directory */

  if(chdir(pw_ent->pw_dir) != 0) {
    fprintf(stderr,
       "%s: Could not chdir to new home directory %s for user #%d:\n%s\n",
       argv[0], pw_ent->pw_dir, real_user, strerror(errno));
    exit(-1);
  }


  /* adapt command name */
  argv[0] = pw_ent->pw_shell;


  /* adapt HOME environment variable */
  strcpy(home_dir, "HOME=");
  strncat(home_dir, pw_ent->pw_dir, MAX_STRING - strlen(home_dir));
  putenv(home_dir);

  /* execute shell */
  execve(SHELL, argv, envp);

  return 0;
}
