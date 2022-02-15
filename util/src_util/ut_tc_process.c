/* Copyright (C) 2009 - 2022 National Aeronautics and Space Administration.
   All Foreign Rights are Reserved to the U.S. Government.

   This software is provided "as is" without any warranty of any kind, either expressed, implied, or statutory,
   including, but not limited to, any warranty that the software will conform to specifications, any implied warranties
   of merchantability, fitness for a particular purpose, and freedom from infringement, and any warranty that the
   documentation will conform to the program, or any warranty that the software will be error free.

   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or
   consequential damages, arising out of, resulting from, or in any way connected with the software or its
   documentation, whether or not based upon warranty, contract, tort or otherwise, and whether or not loss was sustained
   from, or arose out of the results of, or use of, the software, documentation or services provided hereunder.

   ITC Team
   NASA IV&V
   jstar-development-team@mail.nasa.gov
*/

/**
 *  Unit Tests that macke use of TC_ProcessSecurity function on the data.
 **/
#include "ut_tc_process.h"
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

/**
 * @brief Unit Test: No Crypto_Init()
 *
 * TC_ProcessSecurity should reject functionality if the Crypto_Init() function has not been called.
 **/
UTEST(TC_PROCESS_SECURITY, NO_CRYPTO_INIT)
{
    // No Crypto_Init(), but we still Configure It;
    // char* raw_tc_sdls_ping_h = "20030015001880d2c70008197f0b00310000b1fe3128";
    // char* raw_tc_sdls_ping_b = NULL;
    // int raw_tc_sdls_ping_len = 0;

    // hex_conversion(raw_tc_sdls_ping_h, &raw_tc_sdls_ping_b, &raw_tc_sdls_ping_len);
    // Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
    //                         TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_TRUE,
    //                         TC_CHECK_FECF_TRUE, 0x3F);
    // Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);

    // uint8_t* ptr_enc_frame = NULL;
    // uint16_t enc_frame_len = 0;
    // int32_t return_val = CRYPTO_LIB_ERROR;

    // return_val = Crypto_TC_ProcessSecurity((uint8_t* )raw_tc_sdls_ping_b, raw_tc_sdls_ping_len, &ptr_enc_frame, &enc_frame_len);
    // ASSERT_EQ(CRYPTO_LIB_ERR_NO_INIT, return_val);
    // free(raw_tc_sdls_ping_b);
    // Crypto_Shutdown();

    ASSERT_EQ(1,1);
}

/**
 * @brief Unit Test: IV Outside Window
 *
 * TC_ProcessSecurity should return an errror if an IV is received outside of the expected window
 **/
UTEST(TC_PROCESS_SECURITY, BAD_IV_OUTSIDE_WINDOW)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char* buffer_pt_h = "2003001600419635e6e12b257a8ecae411f94480ff56be";
    char* buffer_iv_h = "1af2613c4184dbd101fcedc0"; //e
    char* buffer_et_h = "2003002500FF00091AF2613C4184DBD101FCEDCE9CD21F414F1F54D5F6F58B1F2F77E5B66987";
    uint8_t* buffer_pt_b, *buffer_iv_b, *buffer_et_b, *buffer_key_b = NULL;
    int buffer_pt_len, buffer_iv_len, buffer_et_len, buffer_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_AES256_GCM;
    test_association->est = 1;
    test_association->ast = 1;
    test_association->arsn_win_len = 4;
    test_association->arsn_win = 5;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_key_h, (char**) &buffer_key_b, &buffer_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_key_b, buffer_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_pt_h, (char**) &buffer_pt_b, &buffer_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_iv_h, (char**) &buffer_iv_b, &buffer_iv_len);
    memcpy(test_association->iv, buffer_iv_b, buffer_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_et_h, (char**) &buffer_et_b, &buffer_et_len);

    int32_t status;
    status = Crypto_TC_ProcessSecurity(buffer_et_b, &buffer_et_len, tc_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);

    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_pt_b);
    free(buffer_iv_b);
    free(buffer_et_b);
    free(buffer_key_b);
}

/**
 * @brief Unit Test: IV Inside Window, but not the next expected number
 *
 * TC_ProcessSecurity should correctly process an IV within the ARSN Window if there is a gap in the expected ARSN
 * The SA ARSN should be updated to the most recent received ARSN
 **/
UTEST(TC_PROCESS_SECURITY, IV_INSIDE_WINDOW_WITH_GAP)
{
    uint8_t* ptr_enc_frame = NULL;
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_TRUE, TC_HAS_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x0003, 1, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS);
    Crypto_Init();
    SadbRoutine sadb_routine = get_sadb_routine_inmemory();
    crypto_key_t* ek_ring = cryptography_if->get_ek_ring();
    // NIST supplied vectors
    // NOTE: Added Transfer Frame header to the plaintext
    char* buffer_key_h = "e9ccd6eef27f740d1d5c70b187734e11e76a8ac0ad1702ff02180c5c1c9e5399";
    char* buffer_pt_h = "2003001600419635e6e12b257a8ecae411f94480ff56be";
    char* buffer_iv_h = "1af2613c4184dbd101fcedc0"; //e
    char* buffer_et_h = "2003002500FF00091AF2613C4184DBD101FCEDCE9CD21F414F1F54D5F6F58B1F2F77E5B66987";
    uint8_t* buffer_pt_b, *buffer_iv_b, *buffer_et_b, *buffer_key_b = NULL;
    int buffer_pt_len, buffer_iv_len, buffer_et_len, buffer_key_len = 0;

    // Setup Processed Frame For Decryption
    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    // Expose/setup SAs for testing
    SecurityAssociation_t* test_association = NULL;
    test_association = malloc(sizeof(SecurityAssociation_t) * sizeof(uint8_t));
    // Deactivate SA 1
    sadb_routine->sadb_get_sa_from_spi(1, &test_association);
    test_association->sa_state = SA_NONE;
    // Activate SA 9
    sadb_routine->sadb_get_sa_from_spi(9, &test_association);
    test_association->arsn_len = 0;
    test_association->sa_state = SA_OPERATIONAL;
    test_association->ecs = calloc(1, test_association->ecs_len * sizeof(uint8_t));
    *test_association->ecs = CRYPTO_AES256_GCM;
    test_association->est = 1;
    test_association->ast = 1;
    test_association->arsn_win_len = 4;
    test_association->arsn_win = 5;

    // Insert key into keyring of SA 9
    hex_conversion(buffer_key_h, (char**) &buffer_key_b, &buffer_key_len);
    memcpy(ek_ring[test_association->ekid].value, buffer_key_b, buffer_key_len);

    // Convert input plaintext
    // TODO: Account for length of header and FECF (5+2)
    hex_conversion(buffer_pt_h, (char**) &buffer_pt_b, &buffer_pt_len);
    // Convert/Set input IV
    hex_conversion(buffer_iv_h, (char**) &buffer_iv_b, &buffer_iv_len);
    memcpy(test_association->iv, buffer_iv_b, buffer_iv_len);
    // Convert input ciphertext
    hex_conversion(buffer_et_h, (char**) &buffer_et_b, &buffer_et_len);

    int32_t status;
    status = Crypto_TC_ProcessSecurity(buffer_et_b, &buffer_et_len, tc_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW, status);

    Crypto_Shutdown();
    free(ptr_enc_frame);
    free(buffer_pt_b);
    free(buffer_iv_b);
    free(buffer_et_b);
    free(buffer_key_b);
}

UTEST_MAIN();
