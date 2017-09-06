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

#include <sys/time.h>
#include <time.h>
#include <assert.h>
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

#include "Storage.hpp"

#include "ScryptEnc.hpp"

#define ENCBLOCK 65536


#ifdef HAVE_CLOCK_GETTIME

static clockid_t clocktouse;

static int getclockres(double * resd)
{
	struct timespec res;

	/*
	 * Try clocks in order of preference until we find one which works.
	 * (We assume that if clock_getres works, clock_gettime will, too.)
	 * The use of if/else/if/else/if/else rather than if/elif/elif/else
	 * is ugly but legal, and allows us to #ifdef things appropriately.
	 */
#ifdef CLOCK_VIRTUAL
	if (clock_getres(CLOCK_VIRTUAL, &res) == 0)
		clocktouse = CLOCK_VIRTUAL;
	else
#endif
#ifdef CLOCK_MONOTONIC
	if (clock_getres(CLOCK_MONOTONIC, &res) == 0)
		clocktouse = CLOCK_MONOTONIC;
	else
#endif
	if (clock_getres(CLOCK_REALTIME, &res) == 0)
		clocktouse = CLOCK_REALTIME;
	else
		return (-1);

	/* Convert clock resolution to a double. */
	*resd = res.tv_sec + res.tv_nsec * 0.000000001;

	return (0);
}

static int getclocktime(struct timespec * ts)
{

	if (clock_gettime(clocktouse, ts))
		return (-1);

	return (0);
}

#else

static int getclockres(double * resd)
{

	*resd = 1.0 / CLOCKS_PER_SEC;

	return (0);
}

static int getclocktime(struct timespec * ts)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL))
		return (-1);
	ts->tv_sec = tv.tv_sec;
	ts->tv_nsec = tv.tv_usec * 1000;

	return (0);
}

#endif

static int getclockdiff(struct timespec * st, double * diffd)
{
	struct timespec en;

	if (getclocktime(&en))
		return (1);
	*diffd = (en.tv_nsec - st->tv_nsec) * 0.000000001 +
	    (en.tv_sec - st->tv_sec);

	return (0);
}

/**
 * scryptenc_cpuperf(opps):
 * Estimate the number of salsa20/8 cores which can be executed per second,
 * and return the value via opps.
 */
int scryptenc_cpuperf(double * opps)
{
	struct timespec st;
	double resd, diffd;
	uint64_t i = 0;

	/* Get the clock resolution. */
	if (getclockres(&resd))
		return (2);

#ifdef DEBUG
	fprintf(stderr, "Clock resolution is %f\n", resd);
#endif

	/* Loop until the clock ticks. */
	if (getclocktime(&st))
		return (2);
	do {
		if (libscrypt_scrypt(NULL, 0, NULL, 0, 16, 1, 1, NULL, 0))
			return (3);

		/* Has the clock ticked? */
		if (getclockdiff(&st, &diffd))
			return (2);
		if (diffd > 0)
			break;
	} while (1);

	/* Count how many scrypts we can do before the next tick. */
	if (getclocktime(&st))
		return (2);
	do {
		/* Do an scrypt. */
		if (libscrypt_scrypt(NULL, 0, NULL, 0, 128, 1, 1, NULL, 0))
			return (3);

		/* We invoked the salsa20/8 core 512 times. */
		i += 512;

		/* Check if we have looped for long enough. */
		if (getclockdiff(&st, &diffd))
			return (2);
		if (diffd > resd)
			break;
	} while (1);

#ifdef DEBUG
	fprintf(stderr, "%ju salsa20/8 cores performed in %f seconds\n",
	    (uintmax_t)i, diffd);
#endif

	/* We can do approximately i salsa20/8 cores per diffd seconds. */
	*opps = i / diffd;
	return (0);
}


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
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Failed to determine scrypt ops per second.");
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

void ScryptEncCtx::setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t salt[32];
	uint8_t hbuf[32];
	uint8_t * key_hmac = &dk[32];
	
	int rc;

	/* Pick values for N, r, p. */
	if ((rc = pickparams(maxmem, maxmemfrac, maxtime)) != 0) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Failed to pick scrypt parameters");
	}

	/* Sanity check. */
	assert((logN > 0) && (logN < 256));

	/* Get some salt. */
	if(mbedtls_ctr_drbg_random(my_prng_ctx, salt, 32)) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Failed to obtain seed");
	}

	/* Generate the derived keys. */
	if (libscrypt_scrypt(passwd, passwdlen, salt, 32, getN(), r, p, dk, 64)) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Abnormal scrypt return code");
	}

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
	memcpy(&header[48], hbuf, 16);

	/* Add header signature (used for verifying password). */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, header, 64);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	memcpy(&header[64], hbuf, 32);
}

void ScryptDecCtx::setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
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

	if (memcmp(&header[48], hbuf, 16) != 0) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Invalid header checksum");
	}

	/*
	 * Check whether the provided parameters are valid and whether the
	 * key derivation function can be computed within the allowed memory
	 * and CPU time, unless the user chose to disable this test.
	 */
	if ((rc = checkparams(maxmem, maxmemfrac, maxtime)) != 0) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "System has too little resources to decrypt input");
	}

	/* Compute the derived keys. */
	if (libscrypt_scrypt(passwd, passwdlen, salt, 32, getN(), r, p, dk, 64)) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Abnormal scrypt return code");
	}

	/* Check header signature (i.e., verify password). */

	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, header, 64);    
	mbedtls_md_hmac_finish(&hctx, hbuf);

	if (memcmp(hbuf, &header[64], 32)) {
		//throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Invalid header HMAC");
		throw Storage::Exception(Storage::Exception::WRONG_PASSPHRASE);
	}
}

/**
 * scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     maxmem, maxmemfrac, maxtime, verbose):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen + 128
 * bytes to outbuf.
 */
void ScryptEncCtx::encrypt(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf, const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];
	
	uint8_t hbuf[32];
	
	setup(passwd, passwdlen, maxmem, maxmemfrac, maxtime);
		
	/* Copy header into output buffer. */
	memcpy(outbuf, header, 96);
	
	/* Encrypt data. */
	mbedtls_aes_context aes;

	size_t nc_off=0;
	unsigned char nonce_counter[16], stream_block[16];
	memset(nonce_counter, 0, 16);
	memset(stream_block, 0, 16);
	mbedtls_aes_init(&aes);
	if(mbedtls_aes_setkey_enc(&aes, key_enc, 32*8)) {
		mbedtls_aes_free(&aes);		
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Failed to set AES key");
		
	}
	mbedtls_aes_crypt_ctr(&aes, inbuflen, &nc_off, nonce_counter, stream_block, inbuf, &outbuf[96]);	
	mbedtls_aes_free(&aes);

	/* Add signature. */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, outbuf, 96 + inbuflen);    
	mbedtls_md_hmac_finish(&hctx, hbuf);
	mbedtls_md_free(&hctx);

	memcpy(&outbuf[96 + inbuflen], hbuf, 32);

	/* Zero sensitive data. */
	// TODO: think about zeroing
	//insecure_memzero(dk, 64);
}

/**
 * scryptdec_buf(inbuf, inbuflen, outbuf, outlen, passwd, passwdlen,
 *     maxmem, maxmemfrac, maxtime, verbose, force):
 * Decrypt inbuflen bytes from inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen.  If ${force} is 1, do not check whether
 * decryption will exceed the estimated available memory or time.
 */
void ScryptDecCtx::decrypt(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf, size_t * outlen, const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime)
{
	uint8_t hbuf[32];
	//uint8_t dk[64];
	uint8_t * key_enc = dk;
	uint8_t * key_hmac = &dk[32];

	/*
	 * All versions of the scrypt format will start with "scrypt" and
	 * have at least 7 bytes of header.
	 */
	if ((inbuflen < 7) || (memcmp(inbuf, "scrypt", 6) != 0)) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Input is not scrypt file");
	}

	/* Check the format. */
	if (inbuf[6] != 0) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Incorrect scrypt file version");
	}

	/* We must have at least 128 bytes. */
	if (inbuflen < 128) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Invalid input length");
	}

	memcpy(header, inbuf, 96);

	/* Parse the header and generate derived keys. */
	setup(passwd, passwdlen, maxmem, maxmemfrac, maxtime);

	/* Decrypt data. */
	mbedtls_aes_context aes;

	mbedtls_aes_init(&aes);
	size_t nc_off=0;
	unsigned char nonce_counter[16], stream_block[16];
	memset(nonce_counter, 0, 16);
	memset(stream_block, 0, 16);
	if(mbedtls_aes_setkey_enc(&aes, key_enc, 32*8)) {
		mbedtls_aes_free(&aes);
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Failed to set AES key");
	}
	mbedtls_aes_crypt_ctr(&aes, inbuflen - 128, &nc_off, nonce_counter, stream_block, &inbuf[96], outbuf);
	mbedtls_aes_free(&aes);

	//*outlen = inbuflen - 128;

	/* Verify signature. */
	mbedtls_md_context_t hctx;	
	
	mbedtls_md_init(&hctx);  
	mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&hctx, key_hmac, 32);
	mbedtls_md_hmac_update(&hctx, inbuf, inbuflen -32);    
	mbedtls_md_hmac_finish(&hctx, hbuf);
	mbedtls_md_free(&hctx);

	if (memcmp(hbuf, &inbuf[inbuflen - 32], 32)) {
		throw Storage::Exception(Storage::Exception::CRYPTO_ERROR, "Invalid overall HMAC");			
	}

	/* Zero sensitive data. */
	// TODO:
	//insecure_memzero(dk, 64);
}
