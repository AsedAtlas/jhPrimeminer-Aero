#include"global.h"
#include <ctime>
#include "ticker.h"

bool MineProbablePrimeChain(CSieveOfEratosthenes*& psieve, primecoinBlock_t* block, mpz_class& bnFixedMultiplier, bool& fNewBlock, unsigned int& nTriedMultiplier, unsigned int& nProbableChainLength, 
							unsigned int& , unsigned int& nPrimesHit, sint32 threadIndex, mpz_class& mpzHash, unsigned int nPrimorialMultiplier);

bool BitcoinMiner(primecoinBlock_t* primecoinBlock, CSieveOfEratosthenes*& psieve, unsigned int threadIndex, unsigned int nonceStep) {
	if (pctx == NULL) { pctx = BN_CTX_new(); }

	primecoinBlock->nonce = 1+threadIndex;
	const unsigned long maxNonce = 0xFFFFFFFF;

	uint32 nTime = getTimeMilliseconds() + 1000*600;
	uint32 loopCount = 0;


	mpz_class mpzHashFactor = 2310; //11 Hash Factor

	time_t unixTimeStart;
	time(&unixTimeStart);
	uint32 nTimeRollStart = primecoinBlock->timestamp - 5;
   uint32 nLastRollTime = getTimeMilliseconds();
	uint32 nCurrentTick = nLastRollTime;
	while( nCurrentTick < nTime && primecoinBlock->serverData.blockHeight == jhMiner_getCurrentWorkBlockHeight(primecoinBlock->threadIndex) )
			{
		nCurrentTick = getTimeMilliseconds();
      // Roll Time stamp every 10 secs.
		if ((primecoinBlock->xptMode) && (nCurrentTick < nLastRollTime || (nLastRollTime - nCurrentTick >= 10000)))
		{
			// when using x.pushthrough, roll time
			time_t unixTimeCurrent;
			time(&unixTimeCurrent);
			uint32 timeDif = unixTimeCurrent - unixTimeStart;
			uint32 newTimestamp = nTimeRollStart + timeDif;
			if( newTimestamp != primecoinBlock->timestamp )
			{
				primecoinBlock->timestamp = newTimestamp;
				primecoinBlock->nonce = 1+threadIndex;
			}
         nLastRollTime = nCurrentTick;
		}

		primecoinBlock_generateHeaderHash(primecoinBlock, primecoinBlock->blockHeaderHash.begin());

		bool fNewBlock = true;
		unsigned int nTriedMultiplier = 0;
		// Primecoin: try to find hash divisible by primorial
        uint256 phash = primecoinBlock->blockHeaderHash;
        mpz_class mpzHash;
        mpz_set_uint256(mpzHash.get_mpz_t(), phash);
        
		while ((phash < hashBlockHeaderLimit || !mpz_divisible_p(mpzHash.get_mpz_t(), mpzHashFactor.get_mpz_t())) && primecoinBlock->nonce < maxNonce) {
			primecoinBlock->nonce += nonceStep;
			if (primecoinBlock->nonce >= maxNonce) { primecoinBlock->nonce = 2+threadIndex; }
			primecoinBlock_generateHeaderHash(primecoinBlock, primecoinBlock->blockHeaderHash.begin());
            phash = primecoinBlock->blockHeaderHash;
            mpz_set_uint256(mpzHash.get_mpz_t(), phash);
		}

		mpz_class mpzPrimorial;mpz_class mpzFixedMultiplier;
		unsigned int nRoundTests = 0;unsigned int nRoundPrimesHit = 0;
		unsigned int nTests = 0;unsigned int nPrimesHit = 0;

		unsigned int nProbableChainLength;
		if (primeStats.tSplit) {
			unsigned int nPrimorialMultiplier = primeStats.nPrimorials[threadIndex%primeStats.nPrimorialsSize];
			Primorial(nPrimorialMultiplier, mpzPrimorial);
			mpzFixedMultiplier = mpzPrimorial / mpzHashFactor;
			MineProbablePrimeChain(psieve, primecoinBlock, mpzFixedMultiplier, fNewBlock, nTriedMultiplier, nProbableChainLength, nTests, nPrimesHit, threadIndex, mpzHash, nPrimorialMultiplier);
		} else {
			unsigned int nPrimorialMultiplier = primeStats.nPrimorials[threadSNum];
			Primorial(nPrimorialMultiplier, mpzPrimorial);
			mpzFixedMultiplier = mpzPrimorial / mpzHashFactor;
		MineProbablePrimeChain(psieve, primecoinBlock, mpzFixedMultiplier, fNewBlock, nTriedMultiplier, nProbableChainLength, nTests, nPrimesHit, threadIndex, mpzHash, nPrimorialMultiplier);
			threadSNum++;if (threadSNum>=primeStats.nPrimorialsSize) { threadSNum = 0; }
#ifdef _WIN32
		threadHearthBeat[threadIndex] = getTimeMilliseconds();
#endif
		if (appQuitSignal)
		{
			printf( "Shutting down mining thread %d.\n", threadIndex);
			return false;
		}
		}
		
	if (appQuitSignal) { printf( "Shutting down mining thread %d.\n", threadIndex);return false; }

		nRoundTests += nTests;
		nRoundPrimesHit += nPrimesHit;

		primecoinBlock->nonce += nonceStep;
		loopCount++;
	}
	
	return true;
}
