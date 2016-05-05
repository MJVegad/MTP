#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
	long ret;
	printf("invoking systemcall.\n");
	char str[]="R 2:2:2:2:2:2 3.4.5.6";
	ret = syscall(326, str);
	if(ret<0)
		exit(1);
	return 0;

}
