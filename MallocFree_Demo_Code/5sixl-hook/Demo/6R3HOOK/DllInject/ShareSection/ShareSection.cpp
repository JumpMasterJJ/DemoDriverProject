// ShareSection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>

#pragma data_seg("Shared") //创建名为Shared的数据段
int a = 0; //数据段Shared中的变量a，此处a必须进行初始化
#pragma data_seg()
int b = 0; //普通全局变量

#pragma comment(linker, "/SECTION:Shared,RWS") //为数据段Shared指定读，写及共享属性。

int main(int argc, char* argv[])
{
	a++;
	b++;
	printf("a:%d, b:%d\n", a, b); 
	system("pause");  
	return 0;
}


