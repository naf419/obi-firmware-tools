// some old unix-y passwd util, modded to read/write to /scratch/etc/passwd

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <pwd.h>
#include <string.h>

char	passwd[] = "/scratch/etc/passwd";
char	temp[]	 = "/var/tmp/ptmp";
struct	passwd *pwd;
char	*pw;
char	pwbuf[10];
char	buf[512];

main(argc, argv)
char *argv[];
{
	char *p;
	int i;
	char saltc[2];
	long salt;
	int u,fi,fo;
	int c;
	int pwlen;
	FILE *tf;
	char *uname;


  uid_t uid = getuid();

  if (argc < 2) {
	pwd = getpwuid(uid);
	uname = pwd->pw_name;
  } else {
	uname = argv[1];
	pwd = getpwnam(uname);
  }
  if (!pwd || ((uid != pwd->pw_uid) && uid)) {
        printf("ERROR");
	goto bex;
  }

  printf("Changing password for %s\n", uname);
	
	while(((pwd=getpwent()) != NULL)&&(strcmp(pwd->pw_name,uname)!=0));
	u = getuid();
	if((pwd==NULL) || (u!=0 && u != pwd->pw_uid))
		{
		printf("Permission denied.\n");
		goto bex;
		}
	endpwent();
	if (pwd->pw_passwd[0] && u != 0) {
		strcpy(pwbuf, getpass("Old password:"));
		pw = crypt(pwbuf, pwd->pw_passwd);
		if(strcmp(pw, pwd->pw_passwd) != 0) {
			printf("Sorry.\n");
			goto bex;
		}
	}
	strcpy(pwbuf, getpass("New password:"));
	pwlen = strlen(pwbuf);
	if (pwlen == 0) {
		printf("Password unchanged.\n");
		goto bex;
	}

	if (strcmp(pwbuf,getpass("Retype new password:")) != 0) {
		printf ("Mismatch - password unchanged.\n");
		goto bex;
	}

	time(&salt);
	salt += getpid();

	saltc[0] = salt & 077;
	saltc[1] = (salt>>6) & 077;
	for(i=0;i<2;i++){
		c = saltc[i] + '.';
		if(c>'9') c += 7;
		if(c>'Z') c += 6;
		saltc[i] = c;
	}
	pw = crypt(pwbuf, saltc);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);

	if(access(temp, 0) >= 0) {
		printf("Temporary file busy -- try again\n");
		goto bex;
	}
	close(creat(temp,0600));
	if((tf=fopen(temp,"w")) == NULL) {
		printf("Cannot create temporary file\n");
		goto bex;
	}

/*
 *	copy passwd to temp, replacing matching lines
 *	with new password.
 */

	while((pwd=getpwent()) != NULL) {
		if(strcmp(pwd->pw_name,uname) == 0) {
			u = getuid();
			if(u != 0 && u != pwd->pw_uid) {
				printf("Permission denied.\n");
				goto out;
			}
			pwd->pw_passwd = pw;
		}
		fprintf(tf,"%s:%s:%d:%d:%s:%s:%s\n",
			pwd->pw_name,
			pwd->pw_passwd,
			pwd->pw_uid,
			pwd->pw_gid,
			pwd->pw_gecos,
			pwd->pw_dir,
			pwd->pw_shell);
	}
	endpwent();
	fclose(tf);

/*
 *	copy temp back to passwd file
 */

	if((fi=open(temp,0)) < 0) {
		printf("Temp file disappeared!\n");
		goto out;
	}
	if((fo=creat(passwd, 0644)) < 0) {
		printf("Cannot recreat passwd file.\n");
		goto out;
	}
	while((u=read(fi,buf,sizeof(buf))) > 0) write(fo,buf,u);

out:
	unlink(temp);

bex:
	exit(1);
}
