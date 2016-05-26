#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
	long ret;
	printf("invoking systemcall.\n");
	char str[]="R L 00:22:4d:af:c8:f7 10.129.26.28 0 3.3.3.3";
	ret = syscall(326, str);
	if(ret<0)
		exit(1);
	return 0;

}
