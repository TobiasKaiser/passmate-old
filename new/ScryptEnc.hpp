#pragma once

#include "libscrypt.h"

#include <mbedtls/ctr_drbg.h>


// "abstract" class - only useful as either ScryptEncCtx or ScryptDecCtx
class ScryptEncDecCtx {
	public:
		void display_params();
		ScryptEncDecCtx() {
			r=0;
			p=0;
			logN=0;
			verbose = false;
			opps_set = false;
			opps = 0.0;
		}

	protected:
		uint32_t r;
		uint32_t p;
		int logN;

		uint64_t getN() { return (uint64_t)(1) << logN; }

		//size_t memlimit;
    	//double maxtime;

    	bool verbose;

    	double GetOpsPerSec() { {if(!opps_set) CalcOpsPerSec();} return opps; }
    	
    	mbedtls_ctr_drbg_context *my_prng_ctx;

		uint8_t header[96];
		uint8_t dk[64];

    private:
  		void CalcOpsPerSec();
    	bool opps_set;
    	double opps;
};

class ScryptEncCtx : public ScryptEncDecCtx {
	public:
		ScryptEncCtx(mbedtls_ctr_drbg_context *my_prng_ctx) : ScryptEncDecCtx() {
			this->my_prng_ctx = my_prng_ctx;
		}
		int setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime);
	
	protected:
		int pickparams(size_t maxmem, double maxmemfrac, double maxtime);
};

class ScryptDecCtx : public ScryptEncDecCtx {
	public:
		ScryptDecCtx(bool force) : ScryptEncDecCtx() {
			this->force = force;
		}

		int setup(const uint8_t * passwd, size_t passwdlen, size_t maxmem, double maxmemfrac, double maxtime);

	protected:
		int checkparams(size_t maxmem, double maxmemfrac, double maxtime);
		bool force;
};

