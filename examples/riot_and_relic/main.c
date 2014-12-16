/*
 * Copyright (C) 2014 Tobias Markmann <tm@ayena.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <relic.h>

int main(void)
{
    printf("Hello World!");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    /*  The following is an example for doing an elliptic-curve Diffie-Hellman 
        key exchange. 
    */

    /* Initialize RELIC */
    assert(core_init() == STS_OK);

    /* Select an elliptic curve configuration */
    if (ec_param_set_any() == STS_OK) {
        ec_param_print();

        bn_t privateA;
        ec_t publicA;
        uint8_t sharedKeyA[MD_LEN];

        bn_t privateB;
        ec_t publicB;
        uint8_t sharedKeyB[MD_LEN];

        bn_null(privateA);
        ec_null(publicA);

        bn_new(privateA);
        ec_new(publicA);

        bn_null(privateB);
        ec_null(publicB);

        bn_new(privateB);
        ec_new(publicB);

        /* User A generates private/public key pair */
        assert(cp_ecdh_gen(privateA, publicA) == STS_OK);

        /* User B generates private/public key pair */
        assert(cp_ecdh_gen(privateB, publicB) == STS_OK);

        /* In a protocol you would exchange the public keys now */

        /* User A calculates shared secret */
        assert(cp_ecdh_key(sharedKeyA, MD_LEN, privateA, publicB) == STS_OK);

        /* User B calculates shared secret */
        assert(cp_ecdh_key(sharedKeyB, MD_LEN, privateB, publicA) == STS_OK);

        /* The secrets should be the same now */
        assert(util_cmp_const(sharedKeyA, sharedKeyB, MD_LEN) == CMP_EQ);

        bn_free(privateA);
        ec_free(publicA);

        bn_free(privateB);
        ec_free(publicB);
        printf("RELIC EC-DH test successful\n");
    }

    /* Finalize RELIC */
    core_clean();

    return 0;
}
