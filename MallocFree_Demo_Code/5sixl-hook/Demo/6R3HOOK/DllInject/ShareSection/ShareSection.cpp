// ShareSection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>

#pragma data_seg("Shared") //������ΪShared�����ݶ�
int a = 0; //���ݶ�Shared�еı���a���˴�a������г�ʼ��
#pragma data_seg()
int b = 0; //��ͨȫ�ֱ���

#pragma comment(linker, "/SECTION:Shared,RWS") //Ϊ���ݶ�Sharedָ������д���������ԡ�

int main(int argc, char* argv[])
{
	a++;
	b++;
	printf("a:%d, b:%d\n", a, b); 
	system("pause");  
	return 0;
}


