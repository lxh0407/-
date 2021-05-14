# DES、RSA加密的tcp聊天程序

##实现主体内容

- 本试验通过随机生成的RSA公私秘钥用于对DES的随机生成秘钥进行加密
- 在通过DES加解密算法对服务器客户端之间的数据进行加解密

## 实现代码

```c++
#include <stdio.h>`

#`include <stdlib.h>`

#`include <string.h>`

#`include <time.h>`

#`include <sys/types.h>`

#`include <sys/socket.h>`

#`include <arpa/inet.h>`

#`define SERVERPORT 8888		//服务器监听端口`

#`define BACKLOG 5			//监听队列长度`

#`define BUFFERSIZE 1024		//缓冲区大小`

#`define DESKEYLENGTH 64		//DES密钥长度`

`//公钥结构体`
`struct PublicKey`
`{`
	`long nE;`
	`long nN;`
`};`
`//RSA参数`
`struct RSAParam`
`{`
	`long p;`
	`long q;`
	`long n;`
	`long f;`
	`long e;`
	`long d;`
	`long s;`
`};`

`int pc_first[64] = {`
	`58,50,42,34,26,18,10,2,`
	`60,52,44,36,28,20,12,4,`
	`62,54,46,38,30,22,14,6,`
	`64,56,48,40,32,24,16,8,`
	`57,49,41,33,25,17,9,1,`
	`59,51,43,35,27,19,11,3,`
	`61,53,45,37,29,21,13,5,`
	`63,55,47,39,31,23,15,7`
`};`

`//逆初始置换表`
`int pc_last[64] = {`
	`40,8,48,16,56,24,64,32,`
	`39,7,47,15,55,23,63,31,`
	`38,6,46,14,54,22,62,30,`
	`37,5,45,13,53,21,61,29,`
	`36,4,44,12,52,20,60,28,`
	`35,3,43,11,51,19,59,27,`
	`34,2,42,10,50,18,58,26,`
	`33,1,41,9,49,17,57,25`
`};`

`/*`
	`16轮迭代运算`
`*/`

`//选择扩展数据表`
`int des_E[48] = {`
	`32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,`
	`12,13,14,15,16,17,16,17,18,19,20,21,`
	`20,21,22,23,24,25,24,25,26,27,28,29,`
	`28,29,30,31,32,1`
`};`

`//置换数据表`
`int des_P[32] = {`
	`16,7,20,21,29,12,28,17,`
	`1,15,23,26,5,18,31,10,`
	`2,8,24,14,32,27,3,9,`
	`19,13,30,6,22,11,4,25`
`};`

`int des_S[8][64] = {`
	`//S1`
	`{`
		`14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,`
		`0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,`
		`4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,`
		`15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13`
	`},`
	`//S2`
	`{`
		`15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,`
		`3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,`
		`0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,`
		`13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9`
	`},`
	`//S3`
	`{`
		`10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,`
		`13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,`
		`13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,`
		`1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12`
	`},`
	`//S4`
	`{`
		`7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,`
		`13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,`
		`10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,`
		`3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14`
	`},`
	`//S5`
	`{`
		`2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,`
		`14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,`
		`4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,`
		`11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3`
	`},`
	`//S6`
	`{`
		`12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,`
		`10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,`
		`9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,`
		`4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13`
	`},`
	`//S7`
	`{`
		`4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,`
		`13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,`
		`1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,`
		`6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12`
	`},`
	`//S8`
	`{`
		`13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,`
		`1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,`
		`7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,`
		`2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11`
	`}`
`};`

`/*`
	`子密钥生成所需数据表`
`*/`

`//等分密钥`
`int pc_keyleft[28] = {`
	`57,49,41,33,25,17,9,1,58,50,42,34,26,18,`
	`10,2,59,51,43,35,27,19,11,3,60,52,44,36`
`};`

`int pc_keyright[28] = {`
	`63,55,47,39,31,23,15,7,62,54,46,38,30,22,`
	`14,6,61,53,45,37,29,21,13,5,28,20,12,4`
`};`

`//密钥循环左移运算`
`int moveleft_keynum[16] = {`
	`1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1`
`};`

`//置换选择`
`int keychoose[48] = {`
	`14,17,11,24,1,5,3,28,15,6,21,10,`
	`23,19,12,4,26,8,16,7,27,20,13,2,`
	`41,52,31,37,47,55,30,40,51,45,33,48,`
	`44,49,39,56,34,53,46,42,50,36,29,32`
`};`

`int subkeys[16][48];		//子密钥数组`
`char textdata[32][64];		//保存数据块的地址`

`void DESCore(char* szBuffer);							//DES核心算法`
`void GenerSubkeys(char* key);							//子密钥生成算法`
`int CheckText(char* szBuffer);							//检测文本长度`
`void CleanSpace(char* szBuffer);						//去除空格`
`void CatText(char* szBuffer, int count);				//拼接文本`
`void GetBits(int num, int* data, int pos, int length);	//获取比特位`
`int GetBytes(int* source, int pos, int length);			//获取字节值`
`void DESEncry(char* szBuffer, char key[]);//加密`
`void DESDecry(char* szBuffer, char key[]);//解密`
`void ReverSubKeys();									//调整子密钥的顺序`


`int TotalRecv(int sock, void* szBuffer, size_t length, int flag);	//接受完整消息`
`void DESAllocGener(int sock);		//生成并分配DES密钥`
`void DESAllocRecv(int sock);		//生成RSA公私钥并接收DES密钥`
`void RSAGetParam();			//初始化RSA参数`
`struct PublicKey GetPublicKey();	//获取当前使用的公钥`
`long RSAEncry(unsigned short nSource, struct PublicKey publickey);	//RSA加密`
`unsigned short RSADecry(long nSource);`
`unsigned long MulMod(unsigned long a, unsigned long b, unsigned long n);		//模乘运算`
`unsigned long PowMod(unsigned long base, unsigned long pow, unsigned long n);	//模幂运算`
`long RabinMillerKnl(unsigned long n);						//拉宾——米勒测试`
`long RabinMiller(unsigned long n, unsigned long loop);		//重复拉宾——米勒测试`
`unsigned long RandomPrime(char bits);					//质数生成函数`
`unsigned long Gcd(unsigned long p, unsigned long q);		//求最大公约数`
`unsigned long Enclid(unsigned long e, unsigned long t_n);	//生成私钥d`
`void SecretChat(int sock, char ipaddr[], char chatkey[]);`


`char chatkey[20] = "testtest";`
`struct RSAParam rsa = { 0 };	//RSA参数`
`struct PublicKey publickey;	//RSA公钥`


`//随机生成DES密钥`
`int GenerateDESKey(char* key)`
`{`
	`//生成密钥长度为64bit，即8字节`

	int i, n;
	for (i = 0; i < 8; i++)
	{
		srand(time(NULL));
		n = rand() % 3;
		switch (n)
		{
		case 0:
		{
			//数字
			key[i] = (char)rand() % 58 + 48;
			break;
		}
		case 1:
		{
			//大写字母
			key[i] = (char)rand() % 91 + 65;
			break;
		}
		case 2:
		{
			//小写字母
			key[i] = (char)rand() % 123 + 97;
			break;
		}
		default:
		{
			return 0;
			break;
		}
		}
	}
	key[i] = '\0';
	
	return 1;

`}`

`//DES加密`
`void DESEncry(char* szBuffer, char key[])`
`{`
	`int i;`
	`int count = 0;		//记录消息分割为数据块的数量`

	//检测文本的长度
	count = CheckText(szBuffer);
	
	GenerSubkeys(key);		//生成16个子密钥
	
	//调用加密算法
	for (i = 0; i < count; i++)
	{
		DESCore(textdata[i]);
	}
	
	//拼接文本
	CatText(szBuffer, count);

`}`

`//DES解密`
`void DESDecry(char* szBuffer, char key[])`
`{`
	`int i;`
	`int count = 0;`

	//检测文本的长度
	count = CheckText(szBuffer);
	
	GenerSubkeys(key);		//生成16个子密钥
	ReverSubKeys();			//调整子密钥的顺序
	
	//调用加密算法
	for (i = 0; i < count; i++)
	{
		DESCore(textdata[i]);
	}
	
	//拼接文本
	CatText(szBuffer, count);

`}`

`//DES核心算法`
`void DESCore(char* szBuffer)`
`{`
	`int i, j;							//循环计数器`
	`int temprow, tempcol;				//S盒行列记录`
	`int data[64];						//文本比特位记录`
	`int dataleft[32], dataright[32];	//等分文本比特位`
	`int templeft[64], tempright[48];	//扩展文本比特位`

	//获取64个数据块
	for (i = 0; i < 8; i++)
	{
		GetBits(szBuffer[i], data, i * 8, 8);
	}
	
	//初始置换
	for (i = 0; i < 64; i++)
	{
		templeft[i] = data[pc_first[i] - 1];
	}
	for (i = 0; i < 32; i++)
	{
		dataleft[i] = templeft[i];
		dataright[i] = templeft[i + 32];
	}
	
	//16轮迭代运算
	for (i = 0; i < 16; i++)
	{
		//保存本轮右半段
		for (j = 0; j < 32; j++)
		{
			templeft[j] = dataright[j];
		}
	
		//选择扩展运算
		for (j = 0; j < 48; j++)
		{
			tempright[j] = dataright[des_E[j] - 1];
		}
	
		//密钥加运算
		for (j = 0; j < 48; j++)
		{
			tempright[j] ^= subkeys[i][j];
		}
	
		//选择压缩运算
		for (j = 0; j < 8; j++)
		{
			//计算行号
			temprow = tempright[j * 6] & 1;
			temprow = temprow << 1;
			temprow = tempright[j * 6 + 5] & 1;
			//计算列号
			tempcol = GetBytes(tempright, j * 6 + 1, 4);
	
			GetBits(des_S[j][temprow * 16 + tempcol], tempright, j * 4, 4);
		}
	
		//置换运算
		for (j = 0; j < 32; j++)
		{
			dataright[j] = tempright[des_P[j] - 1];
		}
	
		//与左半段数据异或作为下一轮的右半段，本轮的原始右半段作为下一轮的左半段
		for (j = 0; j < 32; j++)
		{
			dataright[j] ^= dataleft[j];
			dataleft[j] = templeft[j];
		}
	}
	
	//逆初始置换
	for (i = 0; i < 32; i++)
	{
		templeft[i] = dataright[i];
		templeft[i + 32] = dataleft[i];
	}
	
	for (i = 0; i < 64; i++)
	{
		data[i] = templeft[pc_last[i] - 1];
	}
	
	//将加密后的字符串写回缓冲区
	for (i = 0; i < 8; i++)
	{
		szBuffer[i] = GetBytes(data, i * 8, 8);
	}

`}`

`/*`
	`子密钥生成算法由三部分组成：置换选择、循环左移运算、置换运算。`
`*/`

`//子密钥生成算法`
`void GenerSubkeys(char* key)`
`{`
	`int i, j, z;`
	`int templeft, tempright;`
	`int keydata[64], tempbuff[56];`
	`int keyleft[28], keyright[28];`

	for (i = 0; i < 8; i++)
	{
		GetBits(key[i], keydata, i * 8, 8);
	}
	
	//置换选择
	for (i = 0; i < 28; i++)
	{
		keyleft[i] = keydata[pc_keyleft[i] - 1];
		keyright[i] = keydata[pc_keyright[i] - 1];
	}
	
	//循环左移运算
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < moveleft_keynum[i]; j++)
		{
			templeft = keyleft[0];
			tempright = keyright[0];
			for (z = 0; z < 27; z++)
			{
				keyleft[z] = keyleft[z + 1];
				keyright[z] = keyright[z + 1];
			}
			keyleft[27] = templeft;
			keyright[27] = tempright;
		}
	
		//连接
		for (j = 0; j < 28; j++)
		{
			tempbuff[j] = keyleft[j];
			tempbuff[j + 28] = keyright[j];
		}
	
		//置换选择
		for (j = 0; j < 48; j++)
		{
			subkeys[i][j] = tempbuff[keychoose[j] - 1];
		}
	}

`}`

`/*`
	`辅助函数，用于辅助DES运算`
`*/`

`//检测文本的长度`
`int CheckText(char* szBuffer)`
`{`
	`int i;`
	`int count = 0, length = 0;`

	//检测长度
	length = strlen(szBuffer);
	if (length == 0)
	{
		return count;
	}
	
	//对文本进行分割
	while (length != 0)
	{
		if (length / 8 != 0)
		{
			for (i = 0; i < 8; i++)
			{
				textdata[count][i] = szBuffer[count * 8 + i];
			}
			textdata[count][i] = '\0';
			length -= 8;
			count++;
		}
		else
		{
			if (length == 0)
			{
				break;
			}
			else
			{
				for (i = 0; i < length; i++)
				{
					textdata[count][i] = szBuffer[count * 8 + i];
				}
				for (i = length; i < 8; i++)
				{
					textdata[count][i] = 0x20;
				}
				textdata[count][i] = '\0';
				length = 0;
				count++;
			}
		}
	}
	
	return count;

`}`

`//拼接文本`
`void CatText(char* szBuffer, int count)`
`{`
	`int i, j;`

	for (i = 0; i < count; i++)
	{
		for (j = 0; j < 8; j++)
		{
			szBuffer[i * 8 + j] = textdata[i][j];
		}
	}
	szBuffer[i * 8] = '\0';
	CleanSpace(szBuffer);

`}`

`//去除空格`
`void CleanSpace(char* szBuffer)`
`{`
	`int i;`

	for (i = 0; i < strlen(szBuffer); i++)
	{
		if (szBuffer[i] == 0x20)
		{
			szBuffer[i] = '\0';
		}
	}

`}`

`//获取比特位`
`void GetBits(int num, int* data, int pos, int length)`
`{`
	`int i;`
	`for (i = 0; i < length; i++)`
	`{`
		`data[pos + (length - i - 1)] = (num >> i) & 1;`
	`}`
`}`

`//获取字节值`
`int GetBytes(int* source, int pos, int length)`
`{`
	`int i, result = 0;`

	for (i = 0; i < length; i++)
	{
		result = result | source[pos + i];
		if (i != length - 1)
		{
			result = result << 1;
		}
	}
	
	return result;

`}`

`//调整子密钥的顺序`
`void ReverSubKeys()`
`{`
	`int i, j;`
	`int temp[16][48];`

	for (i = 15; i >= 0; i--)
	{
		for (j = 0; j < 48; j++)
		{
			temp[i][j] = subkeys[15 - i][j];
		}
	}
	for (i = 0; i < 16; i++)
	{
		for (j = 0; j < 48; j++)
		{
			subkeys[i][j] = temp[i][j];
		}
	}

`}`



`//=======================================================`
`//完整接受消息`
`int TotalRecv(int sock, void* szBuffer, size_t length, int flag)`
`{`
	`int nRealSize = 0;`
	`int nReal = 0;`

	//循环接受消息
	while (nReal != -1)
	{
		nReal = recv(sock, ((char*)szBuffer) + nRealSize, length - nRealSize, flag);
		if (nReal + nRealSize > length)
		{
			return -1;
		}
		nRealSize += nReal;
	}
	
	return nRealSize;

`}`




`/*`
	`DES密钥分配`
`*/`

`//生成并发送DES密钥`
`void DESAllocGener(int sock)`
`{`
	`int i, flag;`
	`char szBuffer[BUFFERSIZE];`

	//随机生成DES密钥
	flag = GenerateDESKey(chatkey);
	if (flag)
	{
		printf("Generate DES key successful!\n");
	}
	else
	{
		printf("Generate DES key failed!\n");
		exit(0);
	}
	
	//接收RSA公钥
	flag = recv(sock, (char*)&publickey, BUFFERSIZE, 0);
	if (!flag)
	{
		printf("Receive RSA public key failed!\n");
		exit(0);
	}
	
	//加密DES密钥
	long nEncryDESKey[DESKEYLENGTH / 2];
	unsigned short* pDesKey = (unsigned short*)chatkey;
	for (i = 0; i < DESKEYLENGTH / 2; i++)
	{
		nEncryDESKey[i] = RSAEncry(pDesKey[i], publickey);
	}
	
	//将加密后的DES密钥发送给服务端
	if (sizeof(long) * DESKEYLENGTH / 2 != send(sock, (char*)nEncryDESKey, sizeof(long) * DESKEYLENGTH / 2, 0))
	{
		printf("Send DES key failed!\n");
		exit(0);
	}
	else
	{
		printf("Send DES key successful!\n");
	}

`}`


`//生成RSA公私钥对，并解密DES密钥`
`void ServerToClient(int sock)`
`{`
	`int i;`

	//生成RSA公私钥对
	RSAGetParam();
	publickey = GetPublicKey();
	
	//将公钥发送给客户端
	if (send(sock, (char*)&publickey, sizeof(publickey), 0) != sizeof(publickey))
	{
		printf("Send RSA public key failed!\n");
		exit(0);
	}
	else
	{
		printf("Send RSA public key successful!\n");
	}
	
	//接收加密的DES密钥
	long nEncryDESKey[DESKEYLENGTH / 2];
	if (recv(sock, (char*)nEncryDESKey, DESKEYLENGTH / 2 * sizeof(long), 0) != DESKEYLENGTH / 2 * sizeof(long))
	{
		printf("Receive DES key failed!\n");
		exit(0);
	}
	
	//解密DES密钥
	unsigned short* pDesKey = (unsigned short*)chatkey;
	for (i = 0; i < DESKEYLENGTH / 2; i++)
	{
		pDesKey[i] = RSADecry(nEncryDESKey[i]);
	}

`}`




`/*`
	`RSA`
`*/`

`/*`
	`RSA加解密函数`
`*/`

`//初始化RSA参数`
`void RSAGetParam()`
`{`
	`long t;`

	//随机生成两个素数
	rsa.p = RandomPrime(16);
	rsa.q = RandomPrime(16);
	
	//计算模数及相应的f
	rsa.n = rsa.p * rsa.q;
	rsa.f = (rsa.p - 1) * (rsa.q - 1);
	
	//生成公钥中的e
	do
	{
		rsa.e = rand() % 65536;
		rsa.e |= 1;
	} while (Gcd(rsa.e, rsa.f) != 1);
	
	//生成私钥中的d
	rsa.d = Enclid(rsa.e, rsa.f);
	
	//计算n结尾连续的比特1
	rsa.s = 0;
	t = rsa.n >> 1;
	while (t)
	{
		rsa.s++;
		t >>= 1;
	}

`}`

`//获取公钥函数`
`struct PublicKey GetPublicKey()`
`{`
	`struct PublicKey key;`

	key.nE = rsa.e;
	key.nN = rsa.n;
	
	return key;

`}`

`//RSA加密函数`
`long RSAEncry(unsigned short nSource, struct PublicKey publickey)`
`{`
	`//将字符串转换为二进制块`
	`return PowMod(nSource, publickey.nE, publickey.nN);`
`}`

`//RSA解密函数`
`unsigned short RSADecry(long nSource)`
`{`
	`long nRes = PowMod(nSource, rsa.d, rsa.n);`
	`unsigned short* pRes = (unsigned short*)&nRes;`
	`if (pRes[1] != 0 || pRes[3] != 0 || pRes[2] != 0)`
	`{`
		`return 0;`
	`}`

	return pRes[0];

`}`

`/*`
	`RSA核心函数`
`*/`

`//模乘运算`
`unsigned long MulMod(unsigned long a, unsigned long b, unsigned long n)`
`{`
	`return (a * b) % n;`
`}`

`//模幂运算`
`unsigned long PowMod(unsigned long base, unsigned long pow, unsigned long n)`
`{`
	`unsigned long a = base, b = pow, c = 1;`
	`while (b)`
	`{`
		`while (!(b & 1))`
		`{`
			`b >>= 1;`
			`a = MulMod(a, a, n);`
		`}`
		`b--;`
		`c = MulMod(a, c, n);`
	`}`

	return c;

`}`

`//拉宾——米勒测试,判别是否为质数`
`long RabinMillerKnl(unsigned long n)`
`{`
	`unsigned long a, q, k, v;`
	`unsigned int z;`
	`int i, w;`

	//计算出q,k
	q = n - 1;
	k = 0;
	while (!(q & 1))
	{
		++k;
		q >>= 1;
	}
	
	//随机获取一个数
	a = 2 + rand() % (n - 3);
	v = PowMod(a, q, n);
	if (v == 1)
	{
		return 1;
	}
	
	//循环检验
	for (i = 0; i < k; i++)
	{
		z = 1;
		for (w = 0; w < i; w++)
		{
			z *= 2;
		}
		if (PowMod(a, z * q, n) == n - 1)
		{
			return 1;
		}
	}
	
	return 0;

`}`

`//重复拉宾——米勒测试`
`long RabinMiller(unsigned long n, unsigned long loop)`
`{`
	`int i;`

	for (i = 0; i < loop; i++)
	{
		if (!RabinMillerKnl(n))
		{
			return 0;
		}
	}
	
	return 1;

`}`

`//质数生成函数`
`unsigned long RandomPrime(char bits)`
`{`
	`unsigned long base;`

	do
	{
		base = (unsigned long)1 << (bits - 1);		//保证最高位为1
		base += rand() % base;						//加上一个随机数
		base |= 1;									//保证最低位为1
	} while (!RabinMiller(base, 30));					//进行拉宾——米勒测试30次
	
	return base;

`}`

`//求最大公约数`
`unsigned long Gcd(unsigned long p, unsigned long q)`
`{`
	`unsigned long a = p > q ? p : q;`
	`unsigned long b = p < q ? p : q;`
	`unsigned long t;`

	if (p == q)
	{
		return p;		//若两数相等，最大公约数就是本身
	}
	else
	{
		//辗转相除法
		while (b)
		{
			a = a % b;
			t = a;
			a = b;
			b = t;
		}
	
		return a;
	}

`}`

`//生成私钥中的d`
`unsigned long Enclid(unsigned long e, unsigned long t_n)`
`{`
	`unsigned long max = 0xffffffffffffffff - t_n;`
	`unsigned long i = 1, tmp;`

	while (1)
	{
		if (((i * t_n) + 1) % e == 0)
		{
			return ((i * t_n) + 1) / e;
		}
		i++;
		tmp = (i + 1) * t_n;
		if (tmp > max)
		{
			return 0;
		}
	}
	
	return 0;

`}`


`//======================================`

`//选择执行的身份`
`char ChooseCorS()`
`{`
	`char id;`
	`char input[10];`

	printf("Client or Server?\n");
	scanf("%s", input);
	
	//输入检查
	if (strcmp(input, "c") && strcmp(input, "C") && strcmp(input, "client") && strcmp(input, "Client"))
	{
		if (strcmp(input, "s") && strcmp(input, "S") && strcmp(input, "server") && strcmp(input, "Server"))
		{
			printf("Input error!");
			id = 'e';
		}
		else
		{
			id = 's';
		}
	}
	else
	{
		id = 'c';
	}
	
	return id;

`}`


`//安全聊天`
`void SecretChat(int sock, char ipaddr[], char chatkey[])`
`{`
	`pid_t pid;	//进程标识符`
	`char szInputBuffer[BUFFERSIZE], szRecvBuffer[BUFFERSIZE];`
	`int length = 0;`

	//检查密钥的长度
	if (strlen(chatkey) != 8)
	{
		printf("key length error!\n");
		return;
	}
	
	//创建子进程，进行并发通信
	//如果pid=0,则表示为子进程,否则为父进程
	//父进程负责接收消息后解密并输出到标准输出，子进程负责获取标准输入加密并发送
	pid = fork();
	if (pid != 0)
	{
		//父进程,负责接收消息
		while (1)
		{
			length = recv(sock, szRecvBuffer, BUFFERSIZE, 0);
			if (length <= 0)
			{
				printf("Receive failed!\n");
			}
			else
			{
				DESDecry(szRecvBuffer, chatkey);
				printf("Receive message from<%s>: %s\n", ipaddr, szRecvBuffer);
			}
	
			if (!strcmp(szRecvBuffer, "quit"))
			{
				printf("Quit chat!\n");
				break;
			}
		}
	}
	else
	{
		//子进程，负责发送消息
		while (1)
		{
			scanf("%s", szInputBuffer);
			if (strlen(szInputBuffer) <= 0)
			{
				printf("Input error!\n");
				continue;
			}
			DESEncry(szInputBuffer, chatkey);
			length = send(sock, szInputBuffer, strlen(szInputBuffer) + 1, 0);
			if (length <= 0)
			{
				printf("Send failed!\n");
			}
	
			if (!strcmp(szInputBuffer, "quit"))
			{
				printf("Quit chat!\n");
				break;
			}
		}
	}

`}`

`//服务器连接客户端`
`int ServerToClient()`
`{`
	`int server, client, length;`
	`struct sockaddr_in localaddr;`
	`struct sockaddr_in remoteaddr;`

	//建立服务器socket
	if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Create socket failed!");
		return 0;
	}
	
	//设置服务器地址结构
	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(SERVERPORT);
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	//绑定监听端口
	if (bind(server, (struct sockaddr*)&localaddr, sizeof(struct sockaddr)) == -1)
	{
		perror("Bind port failed!");
		return 0;
	}
	
	//开始监听
	if (listen(server, BACKLOG) == -1)
	{
		perror("Listen failed!");
		return 0;
	}
	printf("Listening...\n");
	
	//接收连接请求
	length = sizeof(struct sockaddr_in);
	if ((client = accept(server, (struct sockaddr*)&remoteaddr, &length)) == -1)
	{
		perror("Accept socket failed!");
		return 0;
	}
	printf("Server: got connection from %s, port %d, socket %d\n", inet_ntoa(remoteaddr.sin_addr), ntohs(remoteaddr.sin_port), client);
	close(server);
	
	//DES密钥分配
	DESAllocRecv(client);
	
	//连接建立，开始聊天
	printf("Begin chat ...\n");
	SecretChat(client, inet_ntoa(remoteaddr.sin_addr), chatkey);
	
	//关闭socket
	close(client);
	
	return 1;

`}`

`//客户端连接服务器`
`int ClientToServer(char serverIpAddr[])`
`{`
	`int client;`
	`struct sockaddr_in serveraddr;`

	//建立客户端socket
	if ((client = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Create socket failed!");
		return 0;
	}
	
	//设置服务器地址结构
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(SERVERPORT);
	serveraddr.sin_addr.s_addr = inet_addr(serverIpAddr);
	
	//连接服务器
	if (connect(client, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) != 0)
	{
		perror("Client connect failed!");
		return 0;
	}
	printf("Connect Success!\n");
	
	//DES密钥分配
	DESAllocGener(client);
	
	//连接已经建立，开始聊天
	printf("Begin chat ...\n");
	SecretChat(client, serverIpAddr, chatkey);
	
	//关闭socket
	close(client);
	
	return 1;

`}`

`int main(int argc, char* argv[]){`
	`char id;				//身份标记`
	`char serveraddr[20];	//服务器IP地址`

	//选择执行的身份
	id = ChooseCorS();
	
	//启动服务
	switch (id)
	{
	case 'c':
	{
		//获取服务器地址
		printf("Please input the server address:\n");
		scanf("%s", serveraddr);
		if (strlen(serveraddr) <= 0 || strlen(serveraddr) > 16)
		{
			printf("Server address input error!");
		}
		else
		{
			//建立连接
			ClientToServer(serveraddr);
		}
	
		break;
	}
	case 's':
	{
		//监听连接
	
		ServerToClient();
	
		break;
	}
	default:
	{
		printf("Id error!");
		break;
	}
	}
	
	return 0;

`}`


```

### 代码解释

- 主体调用为开启客户端，服务器端调用RSA公私秘钥生成函数随机生成公私秘钥，在将RSA公钥发送给客户端
- 客户端调用DES随机秘钥生成函数，接收服务器端发送的RSA公钥，用收到的公钥加密DES秘钥，在将加密的DES秘钥发送给服务器端
- 服务器端接受加密DES秘钥，用RSA私钥解密获得DES秘钥
- 服务器和客户端在调用安全聊天函数进行安全聊天

## 实现结果

![10.JPG](https://i.loli.net/2021/05/14/Np9h2nv7QATcwlx.jpg)

