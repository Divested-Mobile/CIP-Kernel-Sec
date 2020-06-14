#include <stdio.h>
#include <unistd.h>

int main(void)
{
	printf("%d\n", (int)geteuid());
	return 0;
}
