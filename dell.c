#include <stdio.h>
#include <string.h>
#include <time.h>

#define mystr "My own utility. Copyright (C) 2007-2010 hpgl, Russia"

#define allow595B
#define allowA95B
#define allow2A7B

#define fSVCTAG 0
#define fHDDSN 1
#define fHDDold 2
#define t595B 0
#define tD35B 1
#define tA95B 2
#define t2A7B 3

#ifdef allow595B
#define f595B
#endif
#ifdef allowA95B
#define f595B
#endif
#ifdef allow2A7B
#define f595B
#endif

char bSuffix[]="595BD35BA95B2A7B";

char scancods[]="\00\0331234567890-=\010\011qwertyuiop[]\015\377asdfghjkl;'`\377\\zxcvbnm,./";
char encscans[]={0x05,0x10,0x13,0x09,0x32,0x03,0x25,0x11,0x1F,0x17,0x06,0x15, \
                 0x30,0x19,0x26,0x22,0x0A,0x02,0x2C,0x2F,0x16,0x14,0x07,0x18, \
                 0x24,0x23,0x31,0x20,0x1E,0x08,0x2D,0x21,0x04,0x0B,0x12,0x2E};

#ifdef allow2A7B
char chartabl2A7B[72]="012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0";
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

#ifdef f595B
int enc0F2(int num1, int num2, int num3) {return (((~num3 ^ num2) & num1) ^ ~num3);}
int enc0F4(int num1, int num2, int num3) {return (( ~num2 ^ num1) ^ num3); }
int enc0F5(int num1, int num2, int num3) {return (( ~num1 | ~num3) ^ num2); }
#endif
int enc1F2(int num1, int num2, int num3) {return ((( num3 ^ num2) & num1) ^ num3);}
int enc1F4(int num1, int num2, int num3) {return (( num2 ^ num1) ^ num3); }
int enc1F5(int num1, int num2, int num3) {return (( num1 | ~num3) ^ num2); }
int encF3 (int num1, int num2, int num3) {return ((( num1 ^ num2) & num3) ^ num2);}

typedef int (encfuncT2)(encfuncT1 func, int num1, int num2, int num3, int key);

int enc1F1 (encfuncT1 func, int num1, int num2, int num3, int key)
{
	return func(num1,num2,num3)+key;
}

#ifdef f595B
int enc0F1 (encfuncT1 func, int num1, int num2, int num3, int key)
{
	return func(num1,num2,num3)-key;
}
#endif

unsigned int rol(unsigned int t, int bitsrot)
{
	return (t >> (32-bitsrot)) | (t << bitsrot);
}

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

void blockEncode(char *outdata, int *encblock, char btype) {
	if (btype==tD35B)
		blockEncodeF((int *)outdata,encblock,enc1F1,enc1F2,encF3,enc1F4,enc1F5);
#ifdef f595B
	else
		blockEncodeF((int *)outdata,encblock,enc0F1,enc0F2,encF3,enc0F4,enc0F5);
#endif
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

		if (btype==t595B) memcpy(&inData[cnt],&bSuffix[0],4); else
		if (btype==tD35B) memcpy(&inData[cnt],&bSuffix[4],4); else
		if (btype==tA95B) memcpy(&inData[cnt],&bSuffix[0],4); else
		if (btype==t2A7B) memcpy(&inData[cnt],&bSuffix[12],4);
		calcsuffix(bfunc,btype,outbuf);
		memcpy(&inData[cnt+4],outbuf,8);
		encode(inData,23,btype);
		r = outData[0] % 9;
		lenpsw = 0;
		for (cnt=0;cnt<16;cnt++) {
			if ( (btype==t595B) || (btype==tD35B) || (btype==tA95B) ) {
				if ((r <= cnt) && (lenpsw<8)) {
					buf1output[lenpsw++] = scancods[encscans[outData[cnt] % sizeof(encscans)]];
				}
			} else if (btype==t2A7B) {
				buf1output[lenpsw++] = chartabl2A7B[outData[cnt] % sizeof(chartabl2A7B)];
			}
		}
	}
}


void calcsuffix(char bfunc, char btype, char* outbuf) {
	int i,r;
	if (bfunc==fSVCTAG) {
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
			if (bfunc==fHDDSN) r ^= inData[8];
			else if (bfunc==fSVCTAG) r ^= inData[4];
		if (outbuf[i] & 2)
			if (bfunc==fHDDSN) r ^= inData[9];
			else if (bfunc==fSVCTAG) r ^= inData[3];
		if (outbuf[i] & 4)
			if (bfunc==fHDDSN) r ^= inData[10];
			else if (bfunc==fSVCTAG) r ^= inData[2];
		if (outbuf[i] & 8)
			r ^= inData[1];
		if (outbuf[i] & 16)
			r ^= inData[0];
		if ( (btype==t595B) || (btype==tD35B) || (btype==tA95B) ) {
			outbuf[i] = encscans[r % sizeof(encscans)];
		} else if (btype==t2A7B) {
			outbuf[i] = chartabl2A7B[r % sizeof(chartabl2A7B)];
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
		fputs("Input: #",stdout);
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
			if (strncmp(&buf1input[len1+1],&bSuffix[0],4)==0) btype=t595B;
			else
#endif
			if (strncmp(&buf1input[len1+1],&bSuffix[4],4)==0) btype=tD35B;
			else
#ifdef allowA95B
			if (strncmp(&buf1input[len1+1],&bSuffix[8],4)==0) btype=tA95B;
			else
#endif
#ifdef allow2A7B
			if (strncmp(&buf1input[len1+1],&bSuffix[12],4)==0) btype=t2A7B;
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
			char mpw1[20];
			strcpy(mpw1,buf1output);
			psw(bfunc,tA95B,buf1output);
			if (strcmp(mpw1,buf1output)!=0) {
				fputs(" passwordA95B: ",stdout);
				fputs(buf1output,stdout);
			}
		}
		fputs("\n",stdout);
	}
	return 0;
}

