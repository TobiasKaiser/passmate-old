/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include <assert.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>

//#include "crypto_aes.h"
//#include "crypto_aesctr.h"
//#include "crypto_entropy.h"
//#include "humansize.h"
//#include "insecure_memzero.h"
//#include "sha256.h"
//#include "sysendian.h"

//#include "crypto_scrypt.h"
//#include "memlimit.h"
//#include "scryptenc_cpuperf.h"

#include "ScryptEncCPUPerf.hpp"
#include "ScryptEnc.hpp"

#define ENCBLOCK 65536


#define PRIu64 "lu"
#define PRIu32 "u"

void ScryptEncDecCtx::display_params()
{
	
	uint64_t mem_minimum = 128 * r * getN();
	double expected_seconds = 4 * getN() * p / opps;
	size_t memlimit = 0;
	double maxtime = 0;
	//char * human_memlimit = humansize(memlimit);
	//char * human_mem_minimum = humansize(mem_minimum);

	fprintf(stderr, "Parameters used: N = %" PRIu64 "; r = %" PRIu32
	    "; p = %" PRIu32 ";\n", getN(), r, p);
	fprintf(stderr, "    This requires at least %lu bytes of memory "
	    "(%zu available),\n", mem_minimum, memlimit);
	fprintf(stderr, "    and will take approximately %.1f seconds "
	    "(limit: %.1f seconds).\n", expected_seconds, maxtime);

	//free(human_memlimit);
	//free(human_mem_minimum);
}

void ScryptEncDecCtx::CalcOpsPerSec()
{
	int rc;
	if ((rc = scryptenc_cpuperf(&opps)) != 0) {
		//return (rc);
		printf("TODO.......\n");
		exit(1);
	}
}

int ScryptEncCtx::pickparams(size_t maxmem, double maxmemfrac, double maxtime)
{
	size_t memlimit;
	double opslimit;
	double maxN, maxrp;

	/* Figure out how much memory to use. */
	//if (memtouse(maxmem, maxmemfrac, &memlimit))
	//	return (1);
	memlimit = maxmem; // Maxmem has to be within the available system memory.

	/* Figure out how fast the CPU is. */
	opslimit = GetOpsPerSec() * maxtime;

	/* Allow a minimum of 2^15 salsa20/8 cores. */
	if (opslimit < 32768)
		opslimit = 32768;

	/* Fix r = 8 for now. */
	r = 8;

	/*
	 * The memory limit requires that 128Nr <= memlimit, while the CPU
	 * limit requires that 4Nrp <= opslimit.  If opslimit < memlimit/32,
	 * opslimit imposes the stronger limit on N.
	 */
#ifdef DEBUG
	fprintf(stderr, "Requiring 128Nr <= %zu, 4Nrp <= %f\n",
	    memlimit, opslimit);
#endif
	if (opslimit < (double)memlimit / 32) {
		/* Set p = 1 and choose N based on the CPU limit. */
		p = 1;
		maxN = opslimit / (r * 4);
		for (logN = 1; logN < 63; logN += 1) {
			if ((uint64_t)(1) << logN > maxN / 2)
				break;
		}
	} else {
		/* Set N based on the memory limit. */
		maxN = memlimit / (r * 128);
		for (logN = 1; logN < 63; logN += 1) {
			if ((uint64_t)(1) << logN > maxN / 2)
				break;
		}

		/* Choose p based on the CPU limit. */
		maxrp = (opslimit / 4) / ((uint64_t)(1) << logN);
		if (maxrp > 0x3fffffff)
			maxrp = 0x3fffffff;
		p = (uint32_t)(maxrp) / r;
	}

	if (verbose)
		display_params();

	/* Success! */
	return (0);
}

int ScryptDecCtx::checkparams(size_t maxmem, double maxmemfrac, double maxtime)
{
	size_t memlimit;
	double opps;
	double opslimit;
	uint64_t N;
	int rc;

	memlimit = maxmem; // Maxmem has to be within the available system memory.


	/* Sanity-check values. */
	if ((logN < 1) || (logN > 63))
		return (7);
	if ((uint64_t)(r) * (uint64_t)(p) >= 0x40000000)
		return (7);

	/* Are we forcing decryption, regardless of resource limits? */
	if (!force) {
		/* Figure out the maximum amount of memory we can use. */
		//if (memtouse(maxmem, maxmemfrac, &memlimit))
		//	return (1);

		/* Figure out how fast the CPU is. */
		if ((rc = scryptenc_cpuperf(&opps)) != 0)
			return (rc);
		opslimit = opps * maxtime;

		/* Check limits. */
		N = (uint64_t)(1) << logN;
		if ((memlimit / N) / r < 128)
			return (9);
		if ((opslimit / N) / (r * p) < 4)
			return (10);
	} else {
		/* We have no limit. */
		memlimit = 0;
		opps = 0;
	}

	if (verbose)
		display_params();

	/* Success! */
	return (0);
}

int ScryptEncCtx::setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t salt[32];
	uint8_t hbuf[32];
	//SHA256_CTX ctx;
	uint8_t * key_hmac = &dk[32];
	
	int rc;

	/* Pick values for N, r, p. */
	if ((rc = pickparams(maxmem, maxmemfrac, maxtime)) != 0)
		return (rc);

	/* Sanity check. */
	assert((logN > 0) && (logN < 256));

	/* Get some salt. */
	if(mbedtls_ctr_drbg_random(my_prng_ctx, salt, 32))
		return (4);

	/* Generate the derived keys. */
	if (libscrypt_scrypt(passwd, passwdlen, salt, 32, getN(), r, p, dk, 64))
		return (3);

	/* Construct the file header. */
	memcpy(header, "scrypt", 6);
	header[6] = 0;
	header[7] = logN & 0xff;
	uint32_t r_be = htobe32(r);
	memcpy(&header[8], &r_be, sizeof(uint32_t)); 
	uint32_t p_be = htobe32(p);
 	memcpy(&header[12], &p_be, sizeof(uint32_t));
	memcpy(&header[16], salt, 32);

	/* Add header checksum. */
	mbedtls_sha256(header, 48, hbuf, 0);	
	//SHA256_Init(&ctx);
	//SHA256_Update(&ctx, header, 48);
	//SHA256_Final(hbuf, &ctx);
	memcpy(&header[48], hbuf, 16);

	/* Add header signature (used for verifying password). */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, header, 64);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	memcpy(&header[64], hbuf, 32);

	/* Success! */
	return (0);
}

int ScryptDecCtx::setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t salt[32];
	uint8_t hbuf[32];
	
	uint8_t * key_hmac = &dk[32];
	int rc;

	/* Parse N, r, p, salt. */
	logN = header[7];
	uint32_t r_be;
	memcpy(&r_be, &header[8], sizeof(uint32_t));
	r = be32toh(r_be);
	uint32_t p_be;
	memcpy(&p_be, &header[12], sizeof(uint32_t));
	p = be32toh(p_be);
	memcpy(salt, &header[16], 32);

	/* Verify header checksum. */
	mbedtls_sha256(header, 48, hbuf, 0);

	if (memcmp(&header[48], hbuf, 16) != 0)
		return (7);

	/*
	 * Check whether the provided parameters are valid and whether the
	 * key derivation function can be computed within the allowed memory
	 * and CPU time, unless the user chose to disable this test.
	 */
	if ((rc = checkparams(maxmem, maxmemfrac, maxtime)) != 0)
		return (rc);

	/* Compute the derived keys. */
	if (libscrypt_scrypt(passwd, passwdlen, salt, 32, getN(), r, p, dk, 64))
		return (3);

	/* Check header signature (i.e., verify password). */

	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, header, 64);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	if (memcmp(hbuf, &header[64], 32))
		return (11);

	/* Success! */
	return (0);
}

/**
 * scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     maxmem, maxmemfrac, maxtime, verbose):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen + 128
 * bytes to outbuf.
 */
int ScryptEncCtx::encrypt(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf, const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];
	int rc;
	
	uint8_t hbuf[32];
	
	//struct crypto_aes_key * key_enc_exp;
	//struct crypto_aesctr * AES;
	mbedtls_aes_context aes;

	mbedtls_aes_init(&aes);

	/* Generate the header and derived key. */
	if ((rc = setup(passwd, passwdlen, maxmem, maxmemfrac, maxtime)) != 0)
		return (rc);

	/* Copy header into output buffer. */
	memcpy(outbuf, header, 96);

	/* Encrypt data. */
	size_t nc_off=0;
	unsigned char nonce_counter[16], stream_block[16];
	memset(nonce_counter, 0, 16);
	memset(stream_block, 0, 16);
	if(mbedtls_aes_setkey_enc(&aes, key_enc, 32*8))
		return (5);
	mbedtls_aes_crypt_ctr(&aes, inbuflen, &nc_off, nonce_counter, stream_block, inbuf, &outbuf[96]);	

	//if ((key_enc_exp = crypto_aes_key_expand(key_enc, 32)) == NULL)
	//	return (5);
	//if ((AES = crypto_aesctr_init(key_enc_exp, 0)) == NULL)
	//	return (6);
	//crypto_aesctr_stream(AES, inbuf, &outbuf[96], inbuflen);
	//crypto_aesctr_free(AES);
	//crypto_aes_key_free(key_enc_exp);

	/* Add signature. */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, outbuf, 96 + inbuflen);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	memcpy(&outbuf[96 + inbuflen], hbuf, 32);

	/* Zero sensitive data. */
	// TODO: think about zeroing
	//insecure_memzero(dk, 64);

	mbedtls_aes_free(&aes); // TODO: Make sure this always happens

	/* Success! */
	return (0);
}

/**
 * scryptdec_buf(inbuf, inbuflen, outbuf, outlen, passwd, passwdlen,
 *     maxmem, maxmemfrac, maxtime, verbose, force):
 * Decrypt inbuflen bytes from inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen.  If ${force} is 1, do not check whether
 * decryption will exceed the estimated available memory or time.
 */
int ScryptDecCtx::decrypt(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf, size_t * outlen, const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t hbuf[32];
	//uint8_t dk[64];
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];
	int rc;
	
	mbedtls_aes_context aes;

	mbedtls_aes_init(&aes);


	/*
	 * All versions of the scrypt format will start with "scrypt" and
	 * have at least 7 bytes of header.
	 */
	if ((inbuflen < 7) || (memcmp(inbuf, "scrypt", 6) != 0))
		return (7);

	/* Check the format. */
	if (inbuf[6] != 0)
		return (8);

	/* We must have at least 128 bytes. */
	if (inbuflen < 128)
		return (7);

	memcpy(header, inbuf, 96);

	/* Parse the header and generate derived keys. */
	if ((rc = setup(passwd, passwdlen, maxmem, maxmemfrac, maxtime)) != 0)
		return (rc);

	/* Decrypt data. */
	
	size_t nc_off=0;
	unsigned char nonce_counter[16], stream_block[16];
	memset(nonce_counter, 0, 16);
	memset(stream_block, 0, 16);
	if(mbedtls_aes_setkey_enc(&aes, key_enc, 32*8))
		return (5);
	mbedtls_aes_crypt_ctr(&aes, inbuflen - 128, &nc_off, nonce_counter, stream_block, &inbuf[96], outbuf);	

	//if ((key_enc_exp = crypto_aes_key_expand(key_enc, 32)) == NULL)
	//	return (5);
	//if ((AES = crypto_aesctr_init(key_enc_exp, 0)) == NULL)
	//	return (6);
	//crypto_aesctr_stream(AES, &inbuf[96], outbuf, inbuflen - 128);
	//crypto_aesctr_free(AES);
	//crypto_aes_key_free(key_enc_exp);
	

	//*outlen = inbuflen - 128;

	/* Verify signature. */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, inbuf, inbuflen -32);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	if (memcmp(hbuf, &inbuf[inbuflen - 32], 32))
		return (7);

	/* Zero sensitive data. */
	// TODO:
	//insecure_memzero(dk, 64);

	/* Success! */
	return (0);
}