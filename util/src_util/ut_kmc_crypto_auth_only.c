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
 *  Unit Tests that make use of TC_ApplySecurity/TC_ProcessSecurity function on the data with KMC Crypto Service/MariaDB Functionality Enabled.
 **/
#include "crypto.h"
#include "crypto_error.h"
#include "sadb_routine.h"
#include "utest.h"

#include "crypto.h"
#include "shared_util.h"
#include <stdio.h>
#include <mysql/mysql.h>

#ifdef KMC_MDB_RH
    #define CLIENT_CERTIFICATE "/certs/redhat-cert.pem"
    #define CLIENT_CERTIFICATE_KEY "/certs/redhat-key.pem"
#endif

#ifdef KMC_MDB_DB
    #define CLIENT_CERTIFICATE "/certs/debian-cert.pem"
    #define CLIENT_CERTIFICATE_KEY "/certs/debian-key.pem"
#endif

/**
 * @brief Error Function for MDB_DB_RESET
 * 
 * @param con 
 */
void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);
}

/**
 * @brief MariaDB: Table Cleanup for Unit Tests
 * Be sure to use only after initialization
 * TODO: Move to shared function for all Unit Tests
 */
void MDB_DB_RESET()
{
    MYSQL *con = mysql_init(NULL);
    if(sadb_mariadb_config->mysql_mtls_key != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_KEY, sadb_mariadb_config->mysql_mtls_key);
            }
            if(sadb_mariadb_config->mysql_mtls_cert != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CERT, sadb_mariadb_config->mysql_mtls_cert);
            }
            if(sadb_mariadb_config->mysql_mtls_ca != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CA, sadb_mariadb_config->mysql_mtls_ca);
            }
            if(sadb_mariadb_config->mysql_mtls_capath != NULL)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_CAPATH, sadb_mariadb_config->mysql_mtls_capath);
            }
            if (sadb_mariadb_config->mysql_tls_verify_server != CRYPTO_FALSE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &(sadb_mariadb_config->mysql_tls_verify_server));
            }
            if (sadb_mariadb_config->mysql_mtls_client_key_password != NULL)
            {
                mysql_optionsv(con, MARIADB_OPT_TLS_PASSPHRASE, sadb_mariadb_config->mysql_mtls_client_key_password);
            }
            if (sadb_mariadb_config->mysql_require_secure_transport == CRYPTO_TRUE)
            {
                mysql_optionsv(con, MYSQL_OPT_SSL_ENFORCE,&(sadb_mariadb_config->mysql_require_secure_transport));
            }
            //if encrypted connection (TLS) connection. No need for SSL Key
            if (mysql_real_connect(con, sadb_mariadb_config->mysql_hostname,
                    sadb_mariadb_config->mysql_username,
                    sadb_mariadb_config->mysql_password,
                    sadb_mariadb_config->mysql_database,
                    sadb_mariadb_config->mysql_port, NULL, 0) == NULL)
            {
                //0,NULL,0 are port number, unix socket, client flag
                finish_with_error(con);
            }

    printf("Truncating Tables\n");
    char* query = "TRUNCATE TABLE security_associations\n";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to Truncate Table\n");
        finish_with_error(con);
    }
    // SA - 1
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (1,'kmc/test/key130',3,X'01',1,1,12,12,16,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,0,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 1\n");
        finish_with_error(con);
    }
    // SA - 2
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (2,'kmc/test/key130',3,X'01',1,1,12,12,16,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,1,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 2\n");
        finish_with_error(con);
    }
    // SA -3
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (3,'kmc/test/key130',3,X'01',1,1,12,12,16,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,2,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 3\n");
        finish_with_error(con);
    }
    // SA - 4
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (4,'kmc/test/key130',3,X'01',0,1,12,12,16,X'000000000000000000000001',1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,0,44,3,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 4\n");
        finish_with_error(con);
    }
    // SA - 5
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid,acs_len) VALUES (5,'kmc/test/key130',3,X'00',X'01',0,1,0,0,4,16,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,7,0,1);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 5\n");
        finish_with_error(con);
    }
    // SA - 6
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid,acs_len) VALUES (6,'kmc/test/nist_hmacsha256',3,X'00',X'02',0,1,0,0,4,32,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,8,0,1);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 6\n");
        finish_with_error(con);
    }
    // SA - 7
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid,acs_len) VALUES (7,'kmc/test/nist_hmacsha512',3,X'00',X'03',0,1,0,0,4,64,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,9,0,1);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 7\n");
        finish_with_error(con);
    }
    // SA - 8
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid,acs_len) VALUES (8,'kmc/test/nist_hmacsha512',3,X'00',X'03',0,1,0,0,4,16,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,10,0,1);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 8\n");
        finish_with_error(con);
    }
    // SA - 9
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (9,'kmc/test/key130',3,X'01',1,1,12,12,8,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,11,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 9\n");
        finish_with_error(con);
    }
    // SA - 10
    query = "INSERT INTO security_associations (spi,ekid,sa_state,ecs,est,ast,shivf_len,iv_len,stmacf_len,iv,abm_len,abm,arsnw,arsn_len,tfvn,scid,vcid,mapid) VALUES (10,'kmc/test/key130',3,X'01',1,1,12,12,32,X'000000000000000000000001',19,X'00000000000000000000000000000000000000',5,0,0,44,12,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 10\n");
        finish_with_error(con);
    }
}

/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_CMAC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c1c08000001bb40";

    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}
/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_CMAC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns  CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  // Invalid MAC, should fail with error 510
    char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000030001D5636A648ACCC94A4BA1011C6F429CB94C73";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001

    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Encrypted Frame Before Processing:\n");
    for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Processed PDU:\n");
    for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x ", tc_processed_frame->tc_pdu[i]);
    }
    printf("\n");

    ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
    ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_CMAC_LARGE_FRM_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 7, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c1f0600a6ec42999902579dac3a5af6aabe93288e18d5d4046e24cc5df1f8fa06bac515206d5b0dfcc9861db694f3207175b725bfa6e987fadc1e1e417bff0c30a90b143ca737f2fcf02525c6080c38fde4d4da229387339f363ccdabf42a1defa29f711926c8e0a7479e082ec00b495ae53c8e33b5dc001833aa1d909b4b3aecd60bc6b0af62e8febb58fa15979a5d1e37b9ba48d6d1bf4b9d669306375d7f93942908e410492d6535c91245abbb98a0584aa764815bfdcab44d8c0aeff3a2e2c712649497f95e9440bb1b562cb6fa70a5ff5e5fdbcad40a97fa3bf48f0560bc9c7125b758f25a27678996e5ee3a82a5b864672b80888c2d469fe690aca0501d0de3bec247825f3fbd7f51184f8099dd2ffeb140c9aad86ae8ade912eadbcbef0bb821e684366a084f8d65bd9d0acccfae5fb130d8bf27ff855cea8de4a4e249e5bc8ef9732c06d6d578574b9f936ae1837a61369a7871612337df2dc091dadc8386e53aba816f3a162b71c268e07583a0378805a1f435bf437c0e27193cee4b653273d965fc0b42cfd3c094e2ff89f276153d452814ff016bfcc1b5ec313667de1aaddeb2d31dcaa75f88e4ac758556c7a632374089c53852601385c89aa668b70fd735e9053473538614408241ac47f6ef12aff10c2bce36df6afe7610a5a06997680b579953888684543b7cdefc7cc5987459a9255d187c8790284ad1f2ca38a3a3d56d909a03af87f3788e00d1b9887296ea5ff4087306569c2a3581189a70892e01279812151fdb9f8ec71786edd9cddd8652558503aac1904cf542aeebf269b08c5f648145b498be842080ccbdfe14c8cad1f371e706c0c4ed27d963e2e645224510e7d43ddf50daf8225f484ec841c9e642e489bd70fdbc925c532ab988d0f3999e3e1bdc88d5b0dd61e2b8d72a4a994f3efdc19382cdffdb96ea55ee5a389b003fc91ebc493c0949f56dc7b4b6d69d10dbc937f3757fb36b9000bf67d049c9c768a586b14b5166bffb41fc29c1d5613f2aaa2868fd974a95a3461b0c1c0f1ca87eccf7624fd1ffbe2f45463505b649a0b32410182731dfbe23813e88c3b6bdec7e";

    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC256_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 8, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c2008000001bb40";

    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC256_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 8, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* enc_tc_jpl_mmt_scid44_vcid1= "202C202E000006000000020001BF2C970335483451019AE78B4E06CA225484AED0023C4F5E35BB3616FF8B1775ED29";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001

    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Encrypted Frame Before Processing:\n");
    for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Processed PDU:\n");
    for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x ", tc_processed_frame->tc_pdu[i]);
    }
    printf("\n");

    ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
    ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: See test name for description of whats being exercised!
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC512_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 9, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c2408000001bb40";

    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

/**
 * @brief Unit Test: HAPPY_PATH_PROCESS_SEC_HMAC512_AUTH_ONLY
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC512_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 9, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns  CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  // Invalid MAC, should fail with error 510
    char* enc_tc_jpl_mmt_scid44_vcid1= "202C244E0000070000000200019A5F6B4F207EF3489364576AD86C957440762A0BB99E17C92BEA5A74B9D2115683AA103E69E11CCE41720BFE44F5091F310FEDE2D54593CB3767D8B4CD3998C521D2";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001

    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Encrypted Frame Before Processing:\n");
    for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Processed PDU:\n");
    for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x ", tc_processed_frame->tc_pdu[i]);
    }
    printf("\n");

    ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
    ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}
/**
 * @brief Unit Test: HAPPY_PATH_APPLY_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 10, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c2808000001bb40";

    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;
    uint16_t enc_frame_len = 0;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Frame before encryption:\n");
    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    printf("Frame after encryption:\n");
    for (int i=0; i<enc_frame_len; i++)
    {
        printf("%02x ", ptr_enc_frame[i]);
    }
    printf("\n");


    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}


/**
 * @brief Unit Test: HAPPY_PATH_PROCESS_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_HMAC512_TRUNCATED_16BYTE_MAC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 10, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1A0000050001C50827915AEB423F054402D5DC3C67566986"; // Returns  CRYPTO_LIB_ERR_INVALID_HEADER since SN/ARC missing from header
    // char* enc_tc_jpl_mmt_scid44_vcid1= "202C1C1E000005000000050001C7BA93010000000000000000000000007ACC";  // Invalid MAC, should fail with error 510
    char* enc_tc_jpl_mmt_scid44_vcid1= "202C281E000008000000010001ECAF0E9E1BC36A418FD5CA95DB50ECF08A74";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001

    TC_t* tc_processed_frame;
    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);

    hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len);

    uint8_t* ptr_enc_frame = NULL;

    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Encrypted Frame Before Processing:\n");
    for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
    {
        printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
    }
    printf("\n");

    status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    printf("Processed PDU:\n");
    for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x ", tc_processed_frame->tc_pdu[i]);
    }
    printf("\n");

    ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
    ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}


UTEST_MAIN();
