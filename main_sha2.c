#include <msp430.h>

#include "sha2.h"

int sha224_example1(uint32_t * hash);
void sha224_example2(uint32_t * hash);
void sha224_example3(uint32_t * hash);
void sha256_example1(uint32_t * hash);
void sha256_example2(uint32_t * hash);
void sha256_example3(uint32_t * hash);
void sha256_example4(uint32_t * hash);
void sha256_example5(uint32_t * hash);
void sha256_example6(uint32_t * hash);

int main(void){
  int err;
  uint32_t hash[8];
  WDTCTL = WDTPW | WDTHOLD;	// Stop watchdog timer
  /*
  * The following 9 examples are taken the NIST SHA-2 Test Data
  * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf
  */

  err= sha224_example1(&hash[0]);
  sha224_example2(&hash[0]);
  sha224_example3(&hash[0]);
  sha256_example1(&hash[0]);
  sha256_example2(&hash[0]);
  sha256_example3(&hash[0]);
  sha256_example4(&hash[0]);
  sha256_example5(&hash[0]);
  sha256_example6(&hash[0]);

  return (err);


  while(1);
}


int sha224_example1(uint32_t * hash){
  //  Input: 0xff (1 byte)
  //  Expected Result: e33f9d75 e6ae1369 dbabf81b 96b4591a e46bba30 b591a6b6 c62542b5
  int i;
  // Space must be reserved for 64 bytes
  uint32_t message[16];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;

  // expected
  expected[0] = 0xe33f9d75;
  expected[1] = 0xe6ae1369;
  expected[2] = 0xdbabf81b;
  expected[3] = 0x96b4591a;
  expected[4] = 0xe46bba30;
  expected[5] = 0xb591a6b6;
  expected[6] = 0xc62542b5;

  // MSB contains message
  message[0]=0xff000000;
  bytes_to_be_hashed = 1;
  hash_mode = SHA_224;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);

  for (i=0;i<7;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);

}

void sha224_example2(uint32_t * hash){
  //  Input: 0xe5e09924 (4 bytes)
  //  Expected Result: fd19e746 90d29146 7ce59f07 7df31163 8f1c3a46 e510d0e4 9a67062d
	int i;
  // Space must be reserved for 64 bytes
  uint32_t message[16];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;

  // expected
  expected[0] = 0xfd19e746;
  expected[1] = 0x90d29146;
  expected[2] = 0x7ce59f07;
  expected[3] = 0x7df31163;
  expected[4] = 0x8f1c3a46;
  expected[5] = 0xe510d0e4;
  expected[6] = 0x9a67062d;

  // Set message
  message[0]=0xe5e09924;
  bytes_to_be_hashed = 4;
  hash_mode = SHA_224;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<7;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}


void sha224_example3(uint32_t * hash){
  //  Input: 56 bytes of zeros
  //  Output Expected: 5c3e25b6 9d0ea26f 260cfae8 7e23759e 1eca9d1e cc9fbf3c 62266804
	int i;
  // Space must be reserved for 128 bytes
  uint32_t message[32];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;

  // expected
  expected[0] = 0x5c3e25b6;
  expected[1] = 0x9d0ea26f;
  expected[2] = 0x260cfae8;
  expected[3] = 0x7e23759e;
  expected[4] = 0x1eca9d1e;
  expected[5] = 0xcc9fbf3c;
  expected[6] = 0x62266804;
  // Set message
  message[0] = 0x00000000;
  message[1] = 0x00000000;
  message[2] = 0x00000000;
  message[3] = 0x00000000;
  message[4] = 0x00000000;
  message[5] = 0x00000000;
  message[6] = 0x00000000;
  message[7] = 0x00000000;
  message[8] = 0x00000000;
  message[9] = 0x00000000;
  message[10] = 0x00000000;
  message[11] = 0x00000000;
  message[12] = 0x00000000;
  message[13] = 0x00000000;

  bytes_to_be_hashed = 56;
  hash_mode = SHA_224;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<7;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example1(uint32_t * hash){
  //  Input: 0xbd (1 byte)
  //  Expected Result: 68325720 aabd7c82 f30f554b 313d0570 c95accbb 7dc4b5aa e11204c0 8ffe732b
	int i;
  // Space must be reserved for 64 bytes
  uint32_t message[16];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;

  // expected
  expected[0] = 0x68325720;
  expected[1] = 0xaabd7c82;
  expected[2] = 0xf30f554b;
  expected[3] = 0x313d0570;
  expected[4] = 0xc95accbb;
  expected[5] = 0x7dc4b5aa;
  expected[6] = 0xe11204c0;
  expected[7] = 0x8ffe732b;
  // MSB contains message
  message[0]=0xbd000000;

  bytes_to_be_hashed = 1;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example2(uint32_t * hash){
  //  Input: 0xc98c8e55 (4 bytes)
  //  Expected Result: 7abc22c0 ae5af26c e93dbb94 433a0e0b 2e119d01 4f8e7f65 bd56c61c cccd9504
	int i;
  // Space must be reserved for 64 bytes
  uint32_t message[16];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;
  // expected
  expected[0] = 0x7abc22c0;
  expected[1] = 0xae5af26c;
  expected[2] = 0xe93dbb94;
  expected[3] = 0x433a0e0b;
  expected[4] = 0x2e119d01;
  expected[5] = 0x4f8e7f65;
  expected[6] = 0xbd56c61c;
  expected[7] = 0xcccd9504;
  // Set message
  message[0]=0xc98c8e55;

  bytes_to_be_hashed = 4;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example3(uint32_t * hash){
  //  Input: 55 bytes of zeros
  //  Output Expected: 02779466 cdec1638 11d07881 5c633f21 90141308 1449002f 24aa3e80 f0b88ef7
	int i;
  // Space must be reserved for 128 bytes
  uint32_t message[32];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;
  // expected
  expected[0] = 0x02779466;
  expected[1] = 0xcdec1638;
  expected[2] = 0x11d07881;
  expected[3] = 0x5c633f21;
  expected[4] = 0x90141308;
  expected[5] = 0x1449002f;
  expected[6] = 0x24aa3e80;
  expected[7] = 0xf0b88ef7;
  // Set message
  message[0] = 0x00000000;
  message[1] = 0x00000000;
  message[2] = 0x00000000;
  message[3] = 0x00000000;
  message[4] = 0x00000000;
  message[5] = 0x00000000;
  message[6] = 0x00000000;
  message[7] = 0x00000000;
  message[8] = 0x00000000;
  message[9] = 0x00000000;
  message[10] = 0x00000000;
  message[11] = 0x00000000;
  message[12] = 0x00000000;
  message[13] = 0x00000000;

  bytes_to_be_hashed = 55;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example4(uint32_t * hash){
  //  Input: 56 bytes of zeros
  //  Output Expected: d4817aa5 497628e7 c77e6b60 6107042b bba31308 88c5f47a 375e6179 be789fbb
	int i;
  // Space must be reserved for 128 bytes
  uint32_t message[32];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;
  // expected
  expected[0] = 0xd4817aa5;
  expected[1] = 0x497628e7;
  expected[2] = 0xc77e6b60;
  expected[3] = 0x6107042b;
  expected[4] = 0xbba31308;
  expected[5] = 0x88c5f47a;
  expected[6] = 0x375e6179;
  expected[7] = 0xbe789fbb;
  // Set message
  message[0] = 0x00000000;
  message[1] = 0x00000000;
  message[2] = 0x00000000;
  message[3] = 0x00000000;
  message[4] = 0x00000000;
  message[5] = 0x00000000;
  message[6] = 0x00000000;
  message[7] = 0x00000000;
  message[8] = 0x00000000;
  message[9] = 0x00000000;
  message[10] = 0x00000000;
  message[11] = 0x00000000;
  message[12] = 0x00000000;
  message[13] = 0x00000000;

  bytes_to_be_hashed = 56;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example5(uint32_t * hash){
  //  Input: 57 bytes of zeros
  //  Output Expected: 65a16cb7 861335d5 ace3c607 18b5052e 44660726 da4cd13b b745381b 235a1785
	int i;
  // Space must be reserved for 128 bytes
  uint32_t message[32];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;
  // expected
  expected[0] = 0x65a16cb7;
  expected[1] = 0x861335d5;
  expected[2] = 0xace3c607;
  expected[3] = 0x18b5052e;
  expected[4] = 0x44660726;
  expected[5] = 0xda4cd13b;
  expected[6] = 0xb745381b;
  expected[7] = 0x235a1785;
  // Set message
  message[0] = 0x00000000;
  message[1] = 0x00000000;
  message[2] = 0x00000000;
  message[3] = 0x00000000;
  message[4] = 0x00000000;
  message[5] = 0x00000000;
  message[6] = 0x00000000;
  message[7] = 0x00000000;
  message[8] = 0x00000000;
  message[9] = 0x00000000;
  message[10] = 0x00000000;
  message[11] = 0x00000000;
  message[12] = 0x00000000;
  message[13] = 0x00000000;
  message[14] = 0x00000000;

  bytes_to_be_hashed = 57;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

void sha256_example6(uint32_t * hash){
  //  Input: 64 bytes of zeros
  //  Output Expected: f5a5fd42 d16a2030 2798ef6e d309979b 43003d23 20d9f0e8 ea9831a9 2759fb4b
	int i;
  // Space must be reserved for 128 bytes
  uint32_t message[32];
  uint32_t expected[8];
  uint32_t bytes_to_be_hashed;
  short hash_mode;
  // expected
  expected[0] = 0xf5a5fd42;
  expected[1] = 0xd16a2030;
  expected[2] = 0x2798ef6e;
  expected[3] = 0xd309979b;
  expected[4] = 0x43003d23;
  expected[5] = 0x20d9f0e8;
  expected[6] = 0xea9831a9;
  expected[7] = 0x2759fb4b;
  // Set message
  message[0] = 0x00000000;
  message[1] = 0x00000000;
  message[2] = 0x00000000;
  message[3] = 0x00000000;
  message[4] = 0x00000000;
  message[5] = 0x00000000;
  message[6] = 0x00000000;
  message[7] = 0x00000000;
  message[8] = 0x00000000;
  message[9] = 0x00000000;
  message[10] = 0x00000000;
  message[11] = 0x00000000;
  message[12] = 0x00000000;
  message[13] = 0x00000000;
  message[14] = 0x00000000;
  message[15] = 0x00000000;

  bytes_to_be_hashed = 64;
  hash_mode = SHA_256;

  SHA_2( &message[0], bytes_to_be_hashed, hash, hash_mode);
  for (i=0;i<8;i++)
  {
	if (hash[i] != expected[i])
		return(-1);
  }
  return(0);
}

