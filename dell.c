#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define mystr "Dell Laptop Master Password Generator.\nCopyright (C) 2011-2012 dogbert; 2007-2010 hpgl"

#define allow595B
#define allowA95B
#define allow2A7B
#define allow1D3B
#define allow3A5B
#define allow1F5A
#define allow1F66
#define allow6FF1

enum { t595B, tD35B, tA95B, t2A7B, t1D3B, t3A5B, t1F5A, t1F66, t6FF1} biosType;
enum { fSVCTAG, fHDDSN, fHDDold } serialType;
char* bSuffix[] = {"595B", "D35B", "A95B", "2A7B", "1D3B", "3A5B", "1F5A", "1F66", "6FF1"};

char scancods[]="\00\0331234567890-=\010\011qwertyuiop[]\015\377asdfghjkl;'`\377\\zxcvbnm,./";
char encscans[]={0x05,0x10,0x13,0x09,0x32,0x03,0x25,0x11,0x1F,0x17,0x06,0x15, \
                 0x30,0x19,0x26,0x22,0x0A,0x02,0x2C,0x2F,0x16,0x14,0x07,0x18, \
                 0x24,0x23,0x31,0x20,0x1E,0x08,0x2D,0x21,0x04,0x0B,0x12,0x2E};

#ifdef allow2A7B
char chartabl2A7B[72]="012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0";
#endif
#ifdef allow1D3B
char chartabl1D3B[72]="0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0";
#endif

#ifdef allow1F66
char chartabl1F66[72]="0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0";
#endif
#ifdef allow1F66
char chartabl6FF1[72]="08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0";
#endif

unsigned int MD5magic[64]={
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

unsigned char inData[23],outData[16];
char buf1output[32], buf1input[20];
char bug4;

void calcsuffix(char bfunc, char btype, char *outbuf);

void initData(void) {
	*(int *)(&outData[0]) =0x67452301;
	*(int *)(&outData[4]) =0xEFCDAB89;
	*(int *)(&outData[8]) =0x98BADCFE;
	*(int *)(&outData[12])=0x10325476;
}

typedef int (encfuncT1) (int num1, int num2, int num3);

#ifdef allow595B
int enc0F2(int num1, int num2, int num3) {return (((~num3 ^ num2) & num1) ^ ~num3);}
int enc0F4(int num1, int num2, int num3) {return (( ~num2 ^ num1) ^ num3); }
int enc0F5(int num1, int num2, int num3) {return (( ~num1 | ~num3) ^ num2); }
#endif
int enc1F2(int num1, int num2, int num3) {return ((( num3 ^ num2) & num1) ^ num3);}
int enc1F3(int num1, int num2, int num3) {return ((( num1 ^ num2) & num3) ^ num2);}
int enc1F4(int num1, int num2, int num3) {return (( num2 ^ num1) ^ num3); }
int enc1F5(int num1, int num2, int num3) {return (( num1 | ~num3) ^ num2); }
int encF3 (int num1, int num2, int num3) {return ((( num1 ^ num2) & num3) ^ num2);}

typedef int (encfuncT2)(encfuncT1 func, int num1, int num2, int num3, int key);

int enc1F1 (encfuncT1 func, int num1, int num2, int num3, int key)
{
	return func(num1,num2,num3)+key;
}

#ifdef allow595B
int enc0F1 (encfuncT1 func, int num1, int num2, int num3, int key)
{
	return func(num1,num2,num3)-key;
}
#endif


unsigned int rol(unsigned int t, int bitsrot)
{
	return (t >> (32-bitsrot)) | (t << bitsrot);
}

#ifdef allow1D3B
int enc0F6(encfuncT1 func, int num1, int num2, int num3, int num4, int key, int rot)
{
	return rol(func(num1,num2,num3)+num4-key, rot)+num1;
}

int enc0F7(encfuncT1 func, int num1, int num2, int num3, int num4, int key, int rot)
{
	return rol(func(num1,num2,num3)+num4+key, rot)+num1;
}
#endif

void blockEncodeF(int *outdata, int *encblock, encfuncT2 func1,
                  encfuncT1 func2, encfuncT1 func3, encfuncT1 func4, encfuncT1 func5 )
{
	char S[4][4] = {{ 7, 12, 17, 22 },{ 5, 9, 14, 20 },{ 4, 11, 16, 23 },{ 6, 10, 15, 21 }};
	int A,B,C,D,t,i;

	A=outdata[0];
	B=outdata[1];
	C=outdata[2];
	D=outdata[3];

	for (i=0;i<64;i++) {
		t=MD5magic[i];
		switch (i>>4) {
			case 0: t=A+func1(func2,B,C,D, t+encblock[(i) & 15]); break;
			case 1: t=A+func1(func3,B,C,D, t+encblock[(i*5+1) & 15]); break;
			case 2: t=A+func1(func4,B,C,D, t+encblock[(i*3+5) & 15]); break;
			case 3: t=A+func1(func5,B,C,D, t+encblock[(i*7) & 15]); break;
		}
		A=D; D=C; C=B; B+=rol(t,S[i>>4][i&3]);
	};

	outdata[0]+=A;
	outdata[1]+=B;
	outdata[2]+=C;
	outdata[3]+=D;
}

void blockEncode3A5B(int *outdata, int *encblock) 
{
	int A,B,C,D,i,j;

	A=outdata[0];
	B=outdata[1];
	C=outdata[2];
	D=outdata[3];

	for (i=0;i<5;i++) {
		for (j=0;j<4;j++) {

			B = enc0F6(enc0F2,C,A,D,B,MD5magic[4*j]+encblock[4*j],7);
			D = enc0F6(enc0F2,B,C,A,D,MD5magic[4*j+1]+encblock[4*j+1],12);
			A = enc0F6(enc0F2,D,B,C,A,MD5magic[4*j+2]+encblock[4*j+2],17);
			C = enc0F6(enc0F2,A,D,B,C,MD5magic[4*j+3]+encblock[4*j+3],22);
		}
		for (j=0;j<4;j++) {
			B = enc0F6(encF3,C,A,D,B,MD5magic[4*(j+4)]+encblock[4*j+1],5);
			D = enc0F6(encF3,B,C,A,D,MD5magic[4*(j+4)+1]+encblock[(4*j+6)&0xF],9);
			A = enc0F6(encF3,D,B,C,A,MD5magic[4*(j+4)+2]+encblock[(4*j-5)&0xF],14);
			C = enc0F6(encF3,A,D,B,C,MD5magic[4*(j+4)+3]+encblock[4*j],20);
		}
		for (j=3;j>=0;j--) {
			B = enc0F6(enc0F4,C,A,D,B,MD5magic[4*(11-j)]+encblock[(4*j-7)&0xF],4);
			D = enc0F6(enc0F4,B,C,A,D,MD5magic[4*(11-j)+1]+encblock[(4*j-4)&0xF],11);
			A = enc0F6(enc0F4,D,B,C,A,MD5magic[4*(11-j)+2]+encblock[(4*j-1)&0xF],16);
			C = enc0F6(enc0F4,A,D,B,C,MD5magic[4*(11-j)+3]+encblock[4*j+2],23);

		}

		for (j=3;j>=0;j--) {
			B = enc0F6(enc0F5,C,A,D,B,MD5magic[4*(15-j)]+encblock[(4*j+4)&0xF],6);
			D = enc0F6(enc0F5,B,C,A,D,MD5magic[4*(15-j)+1]+encblock[(4*j-5)&0xF],10);
			A = enc0F6(enc0F5,D,B,C,A,MD5magic[4*(15-j)+2]+encblock[4*j+2],15);
			C = enc0F6(enc0F5,A,D,B,C,MD5magic[4*(15-j)+3]+encblock[(4*j-7)&0xF],21);
		}
		outdata[0]+=B;
		outdata[1]+=C;
		outdata[2]+=A;
		outdata[3]+=D;
	};


}

void blockEncode1F66(int *outdata, int *encblock) 
{
//	memset(outdata, 0, 4*4);
//	memset(encblock, 0, 16*4);

	int A,B,C,D,i,j;

	A=outdata[0];
	B=outdata[1];
	C=outdata[2];
	D=outdata[3];

	for (i=0;i<17;i++) {
		A |= 0x100097; B ^= 0xA0008; C |= 0x60606161-i; D ^= 0x50501010+i;
		for (j=0;j<4;j++) {
			A = enc0F6(enc0F2,B,C,D,A,MD5magic[16+4*j]+encblock[4*j],7);
			D = enc0F6(enc0F2,A,B,C,D,MD5magic[16+4*j+1]+encblock[4*j+1],12);
			C = enc0F6(enc0F2,D,A,B,C,MD5magic[16+4*j+2]+encblock[4*j+2],17);
			B = enc0F6(enc0F2,C,D,A,B,MD5magic[16+4*j+3]+encblock[4*j+3],22);
		}
		for (j=0;j<4;j++) {
			A = enc0F6(encF3,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[4*j+1],5);
			D = enc0F6(encF3,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j+6)&0xF],9);
			C = enc0F6(encF3,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[(4*j-5)&0xF],14);
			B = enc0F6(encF3,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[4*j],20);
		}
		//printf("R2 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);
		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4);
			D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11);
			C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16);
			B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23);
		}

		//printf("R3 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);
		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j]+encblock[(4*j+4)&0xF],6);
			D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+1]+encblock[(4*j-5)&0xF],10);
			C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+2]+encblock[4*j+2],15);
			B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+3]+encblock[(4*j-7)&0xF],21);
		}
		outdata[0]+=A;
		outdata[1]+=B;
		outdata[2]+=C;
		outdata[3]+=D;
	};
//	printf("intermediate A: %08x B: %08x C: %08x D: %08x\n", A, B, C, D);

	for (i=0;i<21;i++) {
		A |= 0x97; B ^= 0x08; C |= 0x50501010-i; D ^= 0x60606161+i;
		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4);
			D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11);
			C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16);
			B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23);

		}
//		printf("R1 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);

		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[4*j+4&0xF],6);
			D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j-5)&0xF],10);
			C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[(4*j+2)],15);
			B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[(4*j-7)&0xF],21);
		}
//		printf("R2 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);

		for (j=0;j<4;j++) {
			A = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j]+encblock[4*j],7);
			D = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+1]+encblock[(4*j+1)],12);
			C = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+2]+encblock[(4*j+2)],17);
			B = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+3]+encblock[4*j+3],22);
		}
//		printf("R3 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);

		for (j=0;j<4;j++) {
			A = enc0F6(encF3,B,C,D,A,MD5magic[16+4*j]+encblock[4*j+1],5);
			D = enc0F6(encF3,A,B,C,D,MD5magic[16+4*j+1]+encblock[(4*j+6)&0xF],9);
			C = enc0F6(encF3,D,A,B,C,MD5magic[16+4*j+2]+encblock[(4*j-5)&0xF],14);
			B = enc0F6(encF3,C,D,A,B,MD5magic[16+4*j+3]+encblock[4*j],20);
		}
//		printf("R4 i: %d A: %08x B: %08x C: %08x D: %08x\n", i, A, B, C, D);

		outdata[0]+=A;
		outdata[1]+=B;
		outdata[2]+=C;
		outdata[3]+=D;
	};
//	printf("end A: %08x B: %08x C: %08x D: %08x\n", A, B, C, D);

}

#ifdef allow6FF1
void blockEncode6FF1(int *outdata, int *encblock) 
{
	int A,B,C,D,i,j;

	A=outdata[0];
	B=outdata[1];
	C=outdata[2];
	D=outdata[3];

	for (i=0;i<23;i++) {
		A |= 0xA08097; B ^= 0xA010908; C |= 0x60606161-i; D ^= 0x50501010+i;
		for (j=0;j<4;j++) {
			A = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+32]+encblock[4*j],7);
			D = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+32+1]+encblock[4*j+1],12);
			C = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+32+2]+encblock[4*j+2],17);
			B = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j+32+3]+encblock[4*j+3],22);
		}
		for (j=0;j<4;j++) {
			A = enc0F6(encF3,A,B,C,D,MD5magic[4*j]+encblock[4*j+1],5);
			D = enc0F6(encF3,D,A,B,C,MD5magic[4*j+1]+encblock[(4*j+6)&0xF],9);
			C = enc0F6(encF3,C,D,A,B,MD5magic[4*j+2]+encblock[(4*j-5)&0xF],14);
			B = enc0F6(encF3,B,C,D,A,MD5magic[4*j+3]+encblock[4*j],20);
		}

		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F4,A,B,C,D,MD5magic[4*j+16]+encblock[(4*j-7)&0xF],4);
			D = enc0F6(enc0F4,D,A,B,C,MD5magic[4*j+16+1]+encblock[(4*j-4)&0xF],11);
			C = enc0F6(enc0F4,C,D,A,B,MD5magic[4*j+16+2]+encblock[(4*j-1)&0xF],16);
			B = enc0F6(enc0F4,B,C,D,A,MD5magic[4*j+16+3]+encblock[4*j+2],23);
		}

		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+48]+encblock[(4*j+4)&0xF],6);
			D = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+48+1]+encblock[(4*j-5)&0xF],10);
			C = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+48+2]+encblock[4*j+2],15);
			B = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j+48+3]+encblock[(4*j-7)&0xF],21);
		}
	
		outdata[0]+=A;
		outdata[1]+=B;
		outdata[2]+=C;
		outdata[3]+=D;
	};

	for (i=0;i<17;i++) {
		A |= 0x100097; B ^= 0xA0008; C |= 0x50501010-i; D ^= 0x60606161+i; 
		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F4,A,B,C,D,MD5magic[4*j+16]+encblock[(4*j-7)&0xF],4);   
			D = enc0F6(enc0F4,D,A,B,C,MD5magic[4*j+16+1]+encblock[(4*j-4)&0xF],11);
			C = enc0F6(enc0F4,C,D,A,B,MD5magic[4*j+16+2]+encblock[(4*j-1)&0xF],16);
			B = enc0F6(enc0F4,B,C,D,A,MD5magic[4*j+16+3]+encblock[4*j+2],23);      
		}                                                                              

		for (j=0;j<4;j++) {                                                           
			A = enc0F6(enc0F5,A,B,C,D,MD5magic[4*j+32]+encblock[(4*j+4)&0xF],6);   
			D = enc0F6(enc0F5,D,A,B,C,MD5magic[4*j+32+1]+encblock[(4*j-5)&0xF],10);
			C = enc0F6(enc0F5,C,D,A,B,MD5magic[4*j+32+2]+encblock[4*j+2],15);      
			B = enc0F6(enc0F5,B,C,D,A,MD5magic[4*j+32+3]+encblock[(4*j-7)&0xF],21);
		}

		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j]+encblock[4*j],7);
			D = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+1]+encblock[4*j+1],12);
			C = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+2]+encblock[4*j+2],17);
			B = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j+3]+encblock[4*j+3],22);      
		}                                                                              
		for (j=0;j<4;j++) {                                                            
			A = enc0F6(encF3,A,B,C,D,MD5magic[4*j+48]+encblock[4*j+1],5);            
			D = enc0F6(encF3,D,A,B,C,MD5magic[4*j+48+1]+encblock[(4*j+6)&0xF],9);
			C = enc0F6(encF3,C,D,A,B,MD5magic[4*j+48+2]+encblock[(4*j-5)&0xF],14);    
			B = enc0F6(encF3,B,C,D,A,MD5magic[4*j+48+3]+encblock[4*j],20);            
		}                                                                              
                                                                                               
                                                                                               
	                                                                                       
		outdata[0]+=A;                                                                 
		outdata[1]+=B;
		outdata[2]+=C;                                                                 
		outdata[3]+=D;                                                                 
	};                                                                                  
}
#endif


#ifdef allow1D3B
void blockEncode1D3B(int *outdata, int *encblock) 
{
	int A,B,C,D,i,j;
                                                                                             
	A=outdata[0];
	B=outdata[1];
	C=outdata[2];
	D=outdata[3];
                                                                                             
	for (i=0;i<21;i++) {
		A |= 0x97; B ^= 8; C |= 0x60606161-i; D ^= 0x50501010+i;
		for (j=0;j<4;j++) {
			A = enc0F6(enc0F2,B,C,D,A,MD5magic[4*j]+encblock[4*j],7);
			D = enc0F6(enc0F2,A,B,C,D,MD5magic[4*j+1]+encblock[4*j+1],12);
			C = enc0F6(enc0F2,D,A,B,C,MD5magic[4*j+2]+encblock[4*j+2],17);
			B = enc0F6(enc0F2,C,D,A,B,MD5magic[4*j+3]+encblock[4*j+3],22);
		}
		for (j=0;j<4;j++) {
			A = enc0F6(encF3,B,C,D,A,MD5magic[4*(j+4)]+encblock[4*j+1],5);
			D = enc0F6(encF3,A,B,C,D,MD5magic[4*(j+4)+1]+encblock[(4*j+6)&0xF],9);
			C = enc0F6(encF3,D,A,B,C,MD5magic[4*(j+4)+2]+encblock[(4*j-5)&0xF],14);
			B = enc0F6(encF3,C,D,A,B,MD5magic[4*(j+4)+3]+encblock[4*j],20);
		}
                                                                                             
		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F4,B,C,D,A,MD5magic[4*(3-j)+32]+encblock[(4*j-7)&0xF],4);
			D = enc0F6(enc0F4,A,B,C,D,MD5magic[4*(3-j)+32+1]+encblock[(4*j-4)&0xF],11);
			C = enc0F6(enc0F4,D,A,B,C,MD5magic[4*(3-j)+32+2]+encblock[(4*j-1)&0xF],16);
			B = enc0F6(enc0F4,C,D,A,B,MD5magic[4*(3-j)+32+3]+encblock[4*j+2],23);
		}

		for (j=3;j>=0;j--) {
			A = enc0F6(enc0F5,B,C,D,A,MD5magic[4*(3-j)+48]+encblock[(4*j+4)&0xF],6);
			D = enc0F6(enc0F5,A,B,C,D,MD5magic[4*(3-j)+48+1]+encblock[(4*j-5)&0xF],10);
			C = enc0F6(enc0F5,D,A,B,C,MD5magic[4*(3-j)+48+2]+encblock[4*j+2],15);
			B = enc0F6(enc0F5,C,D,A,B,MD5magic[4*(3-j)+48+3]+encblock[(4*j-7)&0xF],21);
		}
	
		outdata[0]+=A;
		outdata[1]+=B;
		outdata[2]+=C;
		outdata[3]+=D;
	};

}
#endif

void blockEncode(char *outdata, int *encblock, char btype) {
	int i;
	switch(btype) 
	{
		case tD35B:
		{
			blockEncodeF((int *)outdata,encblock,enc1F1,enc1F2,encF3,enc1F4,enc1F5);
			break;
		}
#ifdef allow1F66
		case t1F66:
		{
			blockEncode1F66((int *)outdata,encblock);
			break;
		}
#endif
#ifdef allow1D3B
		case t1D3B:
		{
			blockEncode1D3B((int *)outdata,encblock);
			break;
		}
#endif
#ifdef allow6FF1
		case t6FF1:
		{
			blockEncode6FF1((int *)outdata,encblock);
			break;
		}
#endif
	
		case t3A5B:
		{
			blockEncode3A5B((int *)outdata,encblock);
			break;
		}

		default:
		{
			blockEncodeF((int *)outdata,encblock,enc0F1,enc0F2,encF3,enc0F4,enc0F5);
		}
	}
}

void encode(char *inbuf,int cnt,char btype) {
	int encBlock[16];
	char *ptr;
	initData();
	memcpy(encBlock,inbuf,cnt);
	ptr=&((char *)encBlock)[cnt];
	*ptr++=0x80;
	memset(ptr,0,64-1-cnt);
	encBlock[16-2]=((unsigned int)cnt << 3);
	blockEncode(outData,encBlock,btype);
}

void psw(char bfunc, char btype, char *outbuf) {
	int cnt,lenpsw,r;
	if (bfunc==fHDDold) {
		memcpy(inData,buf1input,11);
		calcsuffix(bfunc,btype,outbuf);
		for (cnt=0;cnt<8;cnt++)
			outbuf[cnt]= scancods[ outbuf[cnt] ];
	} else {
		memset(inData,0,sizeof(inData));

		if (bfunc==fSVCTAG) cnt=7;
		else cnt=11;

		if ((bfunc==fHDDSN) && (btype==tA95B))
			memcpy(inData,&buf1input[3],cnt-3);
		else
			memcpy(inData,buf1input,cnt);
		calcsuffix(bfunc,btype,outbuf);
		memcpy(&inData[cnt],bSuffix[btype],4);
		memcpy(&inData[cnt+4],outbuf,8);
		encode(inData,23,btype);
		r = outData[0] % 9;
		lenpsw = 0;
		for (cnt=0;cnt<16;cnt++) {
			if ( (btype==t595B) || (btype==tD35B) || (btype==tA95B) || (btype == t3A5B) ) {
				if ((r <= cnt) && (lenpsw<8)) {
					buf1output[lenpsw++] = scancods[encscans[outData[cnt] % sizeof(encscans)]];
				}
			} else if ((btype==t2A7B) || (btype == t1F5A) ) { 
				buf1output[lenpsw++] = chartabl2A7B[outData[cnt] % sizeof(chartabl2A7B)];
			} else if (btype==t1D3B) {
				buf1output[lenpsw++] = chartabl1D3B[outData[cnt] % sizeof(chartabl1D3B)];
			} else if (btype==t1F66) {
				buf1output[lenpsw++] = chartabl1F66[outData[cnt] % sizeof(chartabl1F66)];
			} else if (btype==t6FF1) {
				buf1output[lenpsw++] = chartabl6FF1[outData[cnt] % sizeof(chartabl6FF1)];
			}
		}
		buf1output[lenpsw++] = 0;
	}
}

void calcsuffix(char bfunc, char btype, char* outbuf) {
	int i,r;
	inData[12] = inData[0];
	inData[11] = inData[1];
	if (bfunc==fSVCTAG) {
		inData[10] = inData[2];
		inData[9]  = inData[3];
		inData[8]  = inData[4];

		outbuf[0] = inData[4];
		outbuf[1] = (inData[4] >> 5) | (((inData[3] >> 5) | (inData[3] << 3)) & 0xF1);
		outbuf[2] = (inData[3] >> 2);
		outbuf[3] = (inData[3] >> 7) | (inData[2] << 1);
		outbuf[4] = (inData[2] >> 4) | (inData[1] << 4);
	} else if (bfunc==fHDDSN) {
		outbuf[0] = inData[8];
		outbuf[1] = (inData[8] >> 5) | (((inData[9] >> 5) | (inData[9] << 3)) & 0xF1);
		outbuf[2] = (inData[9] >> 2);
		outbuf[3] = (inData[9] >> 7) | (inData[10] << 1);
		outbuf[4] = (inData[10] >> 4) | (inData[1] << 4);
	}
	outbuf[5] = (inData[1] >> 1);
	outbuf[6] = (inData[1] >> 6) | (inData[0] << 2);
	outbuf[7] = (inData[0] >> 3);
	for (i=0;i<8;i++) {
		r = 0xAA;
		if (outbuf[i] & 1)
			r ^= inData[8];
		if (outbuf[i] & 2)
			r ^= inData[9];
		if (outbuf[i] & 4)
			r ^= inData[10];
		if (outbuf[i] & 8)
			r ^= inData[11];
		if (outbuf[i] & 16)
			r ^= inData[12];
		if ( (btype==t595B) || (btype==tD35B) || (btype==tA95B) || (btype==t3A5B) ) {
			outbuf[i] = encscans[r % sizeof(encscans)];
		} else if ( (btype==t2A7B) || (btype==t1F5A) ) {
			outbuf[i] = chartabl2A7B[r % sizeof(chartabl2A7B)];
		} else if (btype==t1D3B) {
			outbuf[i] = chartabl1D3B[r % sizeof(chartabl1D3B)];
		} else if (btype==t1F66) {
			outbuf[i] = chartabl1F66[r % sizeof(chartabl1F66)];
		} else if (btype==t6FF1) {
			outbuf[i] = chartabl6FF1[r % sizeof(chartabl6FF1)];
		}
	}
}

int main(int argc, char *argv[]) {
	unsigned char len,len1,bfunc,eol=1,echo=0, *minus,s2[20];
	signed char btype; int argn=0;

	if (argc>1)
		echo=1;

	if (!echo)
		fputs("" mystr "\n" \
		  "Short service tag should be right padded with '*' up to length 7 chars\n" \
		  "HDD serial number is right 11 chars from real HDDSerNum left padded with '*'\n" \
		  "Some BIOSes has left pad HDD serial number with spaces instead '*'\n",stdout);
		
	while (!feof(stdin)) {
		if ((argc<=1) && argn) break;
		fputs("Input: ",stdout);
		if (argc>1) {
			strncpy(buf1input,argv[++argn],sizeof(buf1input));argc--;
		}
		else {
			if (!eol) while (!feof(stdin) && (fgetc(stdin)!='\n')); eol=0;
			if (fgets(buf1input,16+1+1,stdin)==NULL) {
				if (echo) fputs("\n",stdout);
				break;
			}
		}
		len=strlen(buf1input);
		if (len && (buf1input[len-1]=='\n')) {len--;eol=1;buf1input[len]=0;}
		if (echo) {fputs(buf1input,stdout);fputs("\n",stdout);}
		for (len1=0;len1<len;len1++) {
			if (isalpha(buf1input[len1])) {
				buf1input[len1] = toupper(buf1input[len1]);
			}
		}
		minus=strchr(buf1input,'-');
		if (len==11) {
			if (minus!=NULL) {
				fputs("- Incorrect input\n",stdout);
				continue;
			}
			bfunc=fHDDold;
			fputs("By HDD serial number for older BIOS: ",stdout);
		} else {
			if (len==0) break;
			if (minus==NULL) {
				fputs("- No BIOS type found in input string, must be followed by -595B and other registered\n",stdout);
				continue;
			}
			len1=minus-(unsigned char*)buf1input;

			btype=-1;
#ifdef allow595B
			if (strncmp(&buf1input[len1+1],bSuffix[t595B],4)==0) btype=t595B; else
#endif
			if (strncmp(&buf1input[len1+1],bSuffix[tD35B],4)==0) btype=tD35B; else
#ifdef allowA95B
			if (strncmp(&buf1input[len1+1],bSuffix[tA95B],4)==0) btype=tA95B; else
#endif
#ifdef allow2A7B
			if (strncmp(&buf1input[len1+1],bSuffix[t2A7B],4)==0) btype=t2A7B; else
#endif
#ifdef allow1D3B
			if (strncmp(&buf1input[len1+1],bSuffix[t1D3B],4)==0) btype=t1D3B; else
#endif
#ifdef allow3A5B
			if (strncmp(&buf1input[len1+1],bSuffix[t3A5B],4)==0) btype=t3A5B; else
#endif
#ifdef allow1F66
			if (strncmp(&buf1input[len1+1],bSuffix[t1F66],4)==0) btype=t1F66; else
#endif
#ifdef allow6FF1
			if (strncmp(&buf1input[len1+1],bSuffix[t6FF1],4)==0) btype=t6FF1; else
#endif
#ifdef allow1F5A
			if (strncmp(&buf1input[len1+1],bSuffix[t1F5A],4)==0) btype=t1F5A;
#endif

	
			if (btype<0) {
				fputs("- Invalid service tag in input string, allowed only -D35B and other registered\n",stdout);
				continue;
			}
			struct tm *time1; time_t timer1=time(NULL);
			time1=gmtime(&timer1);
			strftime(s2,sizeof(s2),"%d.%m.%Y %H:%M",time1);
			fputs(s2,stdout);
			fputs(" DELL ",stdout);

			if (len1==7) {
				bfunc=fSVCTAG;
				fputs("service tag: ",stdout);
				fputs(buf1input,stdout);
			} else
			if (len1==11) {
				bfunc=fHDDSN;
				fputs("HDD serial number: ",stdout);
				fputs(buf1input,stdout);
			}
			else {
				fputs("- Incorrect input, must be 7 chars service tag or 11 chars HDD serial number\n",stdout);
				continue;
			}
		}
		psw(bfunc,btype,buf1output);
		fputs(" password: ",stdout);
		fputs(buf1output,stdout);
		if (bug4) fputs(" !bug4 warning - password may not work!",stdout);

		if (btype==t595B) if (bfunc==fSVCTAG) { //to check if A95B bug
			char mpw1[32];
			strncpy(mpw1,buf1output, sizeof(buf1output));
			psw(bfunc,tA95B,buf1output);
			if (strcmp(mpw1,buf1output)!=0) {
				fputs(" password A95B: ",stdout);
				fputs(buf1output,stdout);
			}
		}
		fputs("\n",stdout);
	}
	return 0;
}

