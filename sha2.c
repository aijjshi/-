/*--版权所有--，BSD
*版权所有（c）2012，德克萨斯仪器公司
*保留所有权利。
*
*以源代码和二进制形式重新分发和使用，有无
*如果满足以下条件，则允许修改
*满足以下条件：
*
**源代码的重新分发必须保留上述版权
*请注意，此条件列表和以下免责声明。
*
**二进制形式的重新分发必须复制上述版权
*请注意，此条件列表和以下免责声明
*分发时提供的文件和/或其他材料。
*
**德克萨斯仪器公司的名称和
*其贡献者可用于支持或推广衍生产品
*未经事先书面许可，不得使用本软件。
*
*本软件由版权所有人和贡献者“按原样”提供
*以及任何明示或暗示的保证，包括但不限于：，
*对特定产品的适销性和适用性的默示保证
*不承认目的。在任何情况下，版权所有人或
*出资人对任何直接、间接、附带、特殊、，
*惩戒性或后果性损害（包括但不限于，
*替代货物或服务的采购；使用、数据或利润损失；
*或业务中断），无论是何种原因造成的，根据任何责任理论，
*无论是合同、严格责任还是侵权行为（包括疏忽或
*否则）因使用本软件而产生，
*即使被告知可能发生此类损坏。
*--/版权所有--*/
/*
*sha2。c
*
*创建日期：2012年3月13日
*作者：Jace Hall
*
*说明：FIPS PUB 180-3定义的SHA-256的实施：
*官方SHA-256标准
*/
/*===================================================================
//名称：void SHA\u 256（uint32\u t*消息，uint64\u t Mbit\u长度，uint32\u t*哈希）；
//
//简介：用于对消息引用的数据执行SHA-256哈希算法。
//*哈希将包含函数完成时的最终哈希。
//
//输入：uint32\u t*Message—指向要散列的32位长数组的指针。数组的大小必须是哈希块的倍数。（即512位或16个32位长）
//uint64\u t Mbit\u Length—64位值，包含
//要在消息[]中散列的位。
//**注意：如果Mbit\U长度%（mod）512>=448位，则
//需要额外的哈希块。使用者
//必须分配额外的512位
//uint32\u t*哈希—指向哈希数组的指针。最终哈希将存储在此处。
//数组大小应等于8个32位长
//短模式——如果模式==“0”，则使用SHA-224，其他所有模式使用SHA-256
//
//输出：存储在给定指针上的结果。最终哈希存储在哈希指针处。
//
//工艺流程：
//
//注：
//
//更改：
//日期世界卫生组织详情
//2012年3月13日JH原代码
//2012年3月26日，添加了JH评论。
//预处理中途工作
//2012年4月13日JH预处理工作
//2012年5月8日，为SHA-224添加了JH模式以及SHA-224的初始哈希值
//2012年6月11日，JH SHA算法与NIST测试向量匹配。通过
//2012年7月9日，添加了JH版权和其他评论。更改了文件名。
//2014年8月13日224的固定初始哈希值，字节%4=0屏蔽问题
//==================================================================*/
/*开发此代码是为了在MSP430上实现SHA-244/256。
*到目前为止，这段代码还没有得到优化。
*目标是在MSP430上开发一个可理解的SHA-2实现
*该算法将用作函数调用，输入是指向消息的指针
*需要加密，消息的长度（以long为单位）和指向
*哈希（大小为8个long）数组，其中将在函数完成后包含答案。
*/

#include "sha2.h"

/***SHA-XYZ初始哈希值和常量************************/
/*SHA-256的哈希常量字K：*/
static const uint32_t K256[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf,
								  0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
								  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
								  0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
								  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
								  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
								  0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
								  0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
								  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c,
								  0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
								  0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
								  0xc67178f2};

/*SHA-256的初始哈希值H：*/
static const uint32_t Initial_Hash[8] = {0x6a09e667, 0xbb67ae85,
										 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
// SHA-224的初始哈希值
static const uint32_t Initial_Hash_224[8] = {0xc1059ed8, 0x367cd507,
											 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

/*作用*/
/*
 *功能：SHA\U 2
 *执行SHA-256和SHA-224哈希
 *
 *输入：
 *Message：指向要散列的消息的MSB的指针
 *备注：！邮件必须是大端字符
 *               !调用SHA\U 2的函数必须以倍数形式保留额外空间
 *消息后64个字节的大小，以便填充操作
 *待执行。如果MessageLengthBytes%64>55，则会增加64个字节
 *需要在邮件末尾保留。
 *MessageLengthBytes：要散列的消息的长度，以字节为单位
 *哈希：指向将放置哈希的位置的MSB的指针
 *备注：！此位置不应与邮件的位置相同
 *               !调用SHA\U 2的函数必须在此位置保留32字节
 *模式：确定是SHA-224（模式=0）还是SHA-256（模式=1）哈希
 *将执行
 */
void SHA_2(uint32_t *Message, uint32_t MessageLengthBytes, uint32_t *Hash, short mode)
{

	uint64_t Mbit_Length = MessageLengthBytes * 8;

	/*变量声明位于此处*/

	unsigned int leftoverlong = 0;
	unsigned int leftoverbits = 0;
	uint64_t Nblocks = 0;
	unsigned int i = 0;
	unsigned int p = 0;
	unsigned int v = 0;
	uint64_t M_Length;
	uint32_t onemask = 0;
	uint32_t zeromask = 0;

	/*预处理：
	 * 1. 初始化哈希值2。解析消息块3。填充消息块*****/
	if (mode == 0)
	{
		for (i = 0; i <= 7; i++)
		{
			Hash[i] = Initial_Hash_224[i];
		} //初始化SHA-224的哈希
	}
	else
	{
		for (i = 0; i <= 7; i++)
		{
			Hash[i] = Initial_Hash[i];
		} //初始化SHA-256的哈希
	}
	i = 0; // clear i

	/*消息分析*/
	M_Length = Mbit_Length >> 5;	 //将消息的位长度转换为消息中的长度
	Nblocks = M_Length >> 4;		 //整桶数（512位或16个32位桶）
	leftoverlong = M_Length % 16;	 //未装满桶的剩余多头
	leftoverbits = Mbit_Length % 32; //最后一段中的剩余位

	/*消息填充：下一组语句查找消息的结尾，附加1，然后添加0
	 *将消息填充到512bit块。原始消息的长度被解析为最后2个字节**/

	onemask = 0x80000000 >> leftoverbits;
	zeromask = ~(0x7FFFFFFF >> leftoverbits);
	Message[M_Length] = (Message[M_Length] | onemask);
	Message[M_Length] = (Message[M_Length] & zeromask);

	if ((Mbit_Length % 512) < 448)
	{ // Check to see if a new block (chunk) is needed
		// no new chunk needed
		for (v = 1; v < (14 - leftoverlong); v++)
		{
			Message[lastchunk + leftoverlong + v] &= 0x00000000; // zero pad
		}
		Message[lastchunk + 14] = Mbit_Length >> 32; // append bit length to end of chunk
		Message[lastchunk + 15] = Mbit_Length & 0x00000000ffffFFFF;
	}
	else
	{
		// new chunk needed
		for (p = 1; p < (16 - leftoverlong); p++)
		{
			Message[lastchunk + leftoverlong + p] = 0x00000000; // zero out remaining bits in chunk
		}
		for (p = 0; p < 14; p++)
		{
			Message[lastchunk + 16 + p] = 0x00000000; // zero out next chunk
		}
		Message[lastchunk + 30] = Mbit_Length >> 32; // append bit length to end of chunk
		Message[lastchunk + 31] = Mbit_Length & 0x0000FFFF;
	}

	i = 0;
	while (i < (((Mbit_Length + 64) / 512) + ((Mbit_Length + 64) && 0x1FF)))
	{
		// run hash core function
		shaHelper(Message + (16 * i), Hash);
		i++;
	}
}

//对512位执行哈希运算
//*****************************************************************************
//!对512位执行哈希运算
//!
//!\param message是指向要散列的消息的指针
//!\param Hash是指向哈希输出位置的指针（可以是中间值）
//!
//!此函数假定上一个哈希值已位于哈希
//!该消息已转换为正确的格式，并已填充
//!如有必要。
//!
//*****************************************************************************
void shaHelper(uint32_t *message, uint32_t *Hash)
{

	uint32_t W[16] = {0};
	unsigned int i = 0;
	unsigned int t = 0;
	unsigned int counter = 0;
	uint32_t temp1 = 0;
	uint32_t temp2 = 0;
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;

	/*主要算法*/
	/*区块控制。一次处理512位*/
	/*将i-1哈希放入字母中。使用初始哈希值初始化。*/
	a = Hash[0];
	b = Hash[1];
	c = Hash[2];
	d = Hash[3];
	e = Hash[4];
	f = Hash[5];
	g = Hash[6];
	h = Hash[7];

	for (t = 0; t < 64; t++)
	{ //需要更改待办事项/while循环。
		counter++;
		if (t < 16)
		{
			W[t] = message[16 * i + t];
		}
		else
		{
			W[t % 16] = sigma1(W[(t - 2) % 16]) + W[(t - 7) % 16] + sigmaZ(W[(t - 15) % 16]) + W[(t - 16) % 16];
		}

		//算法正确
		temp1 = h + SIG1(e) + Ch(e, f, g) + K256[t] + W[t % 16];
		temp2 = Maj(a, b, c) + SIGZ(a);

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}
	Hash[0] = Hash[0] + a;
	Hash[1] = Hash[1] + b;
	Hash[2] = Hash[2] + c;
	Hash[3] = Hash[3] + d;
	Hash[4] = Hash[4] + e;
	Hash[5] = Hash[5] + f;
	Hash[6] = Hash[6] + g;
	Hash[7] = Hash[7] + h;
}
