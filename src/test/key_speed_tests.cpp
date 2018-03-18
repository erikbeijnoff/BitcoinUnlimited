// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1     ("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj");

BOOST_FIXTURE_TEST_SUITE(key_speed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1;
    BOOST_CHECK(bsecret1.SetString (strSecret1));

    const CKey key1  = bsecret1.GetKey();
    BOOST_CHECK(key1.IsCompressed() == false);
    const CPubKey pubkey1  = key1. GetPubKey();
    BOOST_CHECK(key1.VerifyPubKey(pubkey1));

    std::vector<uint256> signedHashes;
    std::vector<std::vector<unsigned char>> signatures;
    std::vector<std::vector<unsigned char>> compactSignatures;

    const int iterations = 1000;

    for (int n=0; n<iterations; n++) {
        const std::string strMsg = strprintf("Very secret message %i: 11", n);
        const uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
        signedHashes.push_back(hashMsg);

        // normal signatures
        std::vector<unsigned char> sign1;
        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        signatures.push_back(sign1);

        // compact signatures (with key recovery)
        std::vector<unsigned char> csign1;
        BOOST_CHECK(key1.SignCompact(hashMsg, csign1));
        compactSignatures.push_back(csign1);
    }
    {
        const clock_t begin = clock();
        for (size_t i=0; i<signedHashes.size(); i++) {
            pubkey1.Verify(signedHashes[i], signatures[i]);
        }
        const clock_t end = clock();
        const double time = (double)(end - begin) / CLOCKS_PER_SEC;

        printf("Verification of normal signature for %d iterations: %f seconds\n", iterations, time);
    }
    {
        const clock_t begin = clock();
        for (size_t i=0; i<signedHashes.size(); i++) {
            CPubKey rkey1;
            rkey1.RecoverCompact(signedHashes[i], compactSignatures[i]);
        }
        const clock_t end = clock();
        const double time = (double)(end - begin) / CLOCKS_PER_SEC;

        printf("Verification of compact signature for %d iterations: %f seconds\n", iterations, time);
    }
}

BOOST_AUTO_TEST_SUITE_END()
