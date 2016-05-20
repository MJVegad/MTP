#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
	const char *name = "ivshmem";
	const int SIZE = 1048576;

	int shm_fd;
	void *ptr;
	int i;

	/* open the shared memory segment */
	shm_fd = shm_open(name, O_RDWR, 0777);
	//shm_fd = open(name, O_RDWR);

	if (shm_fd == -1) {
		printf("shared memory open failed\n");
		fprintf( stderr, "Open failed:%s\n",
            strerror( errno ) );
		exit(-1);
	}

	/* now map the shared memory segment in the address space of the process */
	ptr = mmap(0,SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (ptr == MAP_FAILED) {
		printf("MMap failed\n");
		exit(-1);
	}

	/* now read from the shared memory region */
	char *p=ptr;
	int flag=0;
	char str[70];
	int j;
	for(;;){
	for(i=0;i<1048576;i++)
	{
		if (p[i]=='@')
		{
			if (flag==1)
			{
				flag=0;
				strcat(str,"\0");
				printf("%s",str);
				int ret = syscall(326, str);
				if(ret<0)
					exit(1);
				printf("%s",str);
				printf("\n");
				//free(str);
				p[i]='$';
			}
			else
			{
				p[i]='$';
				//str=(char*)malloc(70);
				for(j=0;j<70;j++)
					str[j]='\0';
				j=0;
				flag=1;
			}		
		}
		else
		{
			if (p[i]!=NULL && flag==1)
			{
				//strcat(str,&p[i]);
				str[j]=p[i];
				j=j+1;	
			 	//printf("%c",p[i]);
			}	
		}
	}
	}
	/* remove the shared memory segment */
/*	if (shm_unlink(name) == -1) {
		printf("Error removing %s\n",name);
		exit(-1);
	}
*/
	return 0;
}
