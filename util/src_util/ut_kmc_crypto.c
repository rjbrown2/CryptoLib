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
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid) VALUES (5,'kmc/test/key130',3,X'00',X'01',0,1,0,0,4,16,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,7,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 5\n");
        finish_with_error(con);
    }
    // SA - 6
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid) VALUES (6,'kmc/test/nist_hmacsha256',3,X'00',X'02',0,1,0,0,4,32,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,8,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 6\n");
        finish_with_error(con);
    }
    // SA - 7
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid) VALUES (7,'kmc/test/nist_hmacsha512',3,X'00',X'03',0,1,0,0,4,64,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,9,0);";
    if (mysql_real_query(con, query, strlen(query)))
    { // query should be NUL terminated!
        printf("Failed to re-create security_association table for SPI 7\n");
        finish_with_error(con);
    }
    // SA - 8
    query = "INSERT INTO security_associations (spi,akid,sa_state,ecs,acs,est,ast,iv_len,shivf_len,shsnf_len,stmacf_len,arsn,arsn_len,abm_len,abm,arsnw,tfvn,scid,vcid,mapid) VALUES (8,'kmc/test/nist_hmacsha512',3,X'00',X'03',0,1,0,0,4,16,X'00000001',4,1024,X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',5,0,44,10,0);";
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
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c0408000001bd37";
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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
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
//// Commenting out test - AEAD algorithms must have a tag -- Enc only config is invalid
///**
// * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
// **/
//UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_ENC_ONLY)
//{
//    // Setup & Initialize CryptoLib
//    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//    Crypto_Config_MariaDB("sadb_user", "sadb_password", "localhost","sadb", 3306, CRYPTO_FALSE, NULL, NULL, NULL, NULL, 0, NULL);
//    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem", "PEM","/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",NULL,"/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL, NULL, CRYPTO_FALSE);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    int32_t status = Crypto_Init();
//
//    char* raw_tc_jpl_mmt_scid44_vcid1= "202c0808000001361c";
//    char* raw_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//    int raw_tc_jpl_mmt_scid44_vcid1_expect_len = 0;
//
//    hex_conversion(raw_tc_jpl_mmt_scid44_vcid1, &raw_tc_jpl_mmt_scid44_vcid1_expect, &raw_tc_jpl_mmt_scid44_vcid1_expect_len);
//
//    uint8_t* ptr_enc_frame = NULL;
//    uint16_t enc_frame_len = 0;
//
//    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//
//    printf("Frame before encryption:\n");
//    for (int i=0; i<raw_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//    {
//        printf("%02x ", (uint8_t)raw_tc_jpl_mmt_scid44_vcid1_expect[i]);
//    }
//    printf("\n");
//
//    status = Crypto_TC_ApplySecurity((uint8_t* )raw_tc_jpl_mmt_scid44_vcid1_expect, raw_tc_jpl_mmt_scid44_vcid1_expect_len, &ptr_enc_frame, &enc_frame_len);
//    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//    printf("Frame after encryption:\n");
//    for (int i=0; i<enc_frame_len; i++)
//    {
//        printf("%02x ", ptr_enc_frame[i]);
//    }
//    printf("\n");
//
//
//    Crypto_Shutdown();
//    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
//    free(ptr_enc_frame);
//    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//}
/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c0C08000001bf1a";
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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
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
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_ENC_AND_AUTH)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* enc_tc_jpl_mmt_scid44_vcid1= "202C0426000002000000000000000000000001669C5639DCCFEA8C6CE33230EE2E7065496367CC";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001
    // IV=000000000000000000000001
    // AAD=00000000000000000000000000000000000000


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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
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
//// Commenting out test - AEAD algorithms must have a tag -- Enc only config is invalid
///**
// * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
// **/
//UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_ENC_ONLY)
//{
//    // Setup & Initialize CryptoLib
//    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
//                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
//                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
//    Crypto_Config_MariaDB("sadb_user", "sadb_password", "localhost","sadb", 3306, CRYPTO_FALSE, NULL, NULL, NULL, NULL, 0, NULL);
//    Crypto_Config_Kmc_Crypto_Service("https", "asec-cmdenc-srv1.jpl.nasa.gov", 8443, "crypto-service", "/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-cert.pem", "PEM","/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/local-test-key.pem",NULL,"/home/isaleh/git/KMC/CryptoLib-IbraheemYSaleh/util/etc/ammos-ca-bundle.crt", NULL, NULL, CRYPTO_FALSE);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
//    int32_t status = Crypto_Init();
//
//    char* enc_tc_jpl_mmt_scid44_vcid1= "202C0816000003000000000000000000000001669CD238";
//    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
//    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;
//
//    // IV = 000000000000000000000001
//
//    TC_t* tc_processed_frame;
//    tc_processed_frame = malloc(sizeof(uint8_t) * TC_SIZE);
//
//    hex_conversion(enc_tc_jpl_mmt_scid44_vcid1, &enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len);
//
//    uint8_t* ptr_enc_frame = NULL;
//
//    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//
//    printf("Encrypted Frame Before Processing:\n");
//    for (int i=0; i<enc_tc_jpl_mmt_scid44_vcid1_expect_len; i++)
//    {
//        printf("%02x ", (uint8_t)enc_tc_jpl_mmt_scid44_vcid1_expect[i]);
//    }
//    printf("\n");
//
//    status = Crypto_TC_ProcessSecurity((uint8_t* )enc_tc_jpl_mmt_scid44_vcid1_expect, &enc_tc_jpl_mmt_scid44_vcid1_expect_len, tc_processed_frame);
//    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//    // Expected to fail -- KMC Crypto Service doesn't support AES/GCM with no AAD/MAC
//    ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);
//    printf("Processed PDU:\n");
//    // for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
//    for (int i=0; i<2; i++)
//    {
//        printf("%02x ", tc_processed_frame->tc_pdu[i]);
//    }
//    printf("\n");
//
//    // ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
//    // ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);
//
//    Crypto_Shutdown();
//    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
//    free(ptr_enc_frame);
//    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
//}
/**
 * @brief Unit Test: Nominal Encryption with KMC Crypto Service && JPL Unit Test MariaDB
 * This doesn't work -- Apply Security Auth Only doesn't return the proper tag.
 **/
UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_AUTH_ONLY)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 0, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 1, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 2, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 3, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* enc_tc_jpl_mmt_scid44_vcid1= "202C0C2600000400000000000000000000000100016E2051F96CAB186BCE364A65AF599AE52F38";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001
    // IV=000000000000000000000001
    // AAD=00000000000000000000000000000000000000


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

    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
    // Expected to fail -- KMC doesn't support 0 cipher text input for decrypt function.
    // ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);
    printf("Processed PDU:\n");
    for (int i=0; i<tc_processed_frame->tc_pdu_len; i++)
    {
        printf("%02x ", tc_processed_frame->tc_pdu[i]);
    }
    printf("\n");

    // ASSERT_EQ(0x00,tc_processed_frame->tc_pdu[0]);
    // ASSERT_EQ( 0x01,tc_processed_frame->tc_pdu[1]);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
    // ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);
}

UTEST(KMC_CRYPTO, HAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* raw_tc_jpl_mmt_scid44_vcid1= "202c2c08000001bd37";
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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
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

UTEST(KMC_CRYPTO, HAPPY_PATH_PROCESS_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* enc_tc_jpl_mmt_scid44_vcid1= "202C2C1E000009000000000000000000000001669C5639DCCFEA8C6CE3AA71";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001
    // IV=000000000000000000000001
    // AAD=00000000000000000000000000000000000000


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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
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

UTEST(KMC_CRYPTO, UNHAPPY_PATH_INVALID_MAC_PROCESS_SEC_ENC_AND_AUTH_AESGCM_8BYTE_MAC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 11, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();

    char* enc_tc_jpl_mmt_scid44_vcid1= "202C2C1E000009000000000000000000000001669C5639DCCDEA8C6CE3EEF2";
    char* enc_tc_jpl_mmt_scid44_vcid1_expect = NULL;
    int enc_tc_jpl_mmt_scid44_vcid1_expect_len = 0;

    // Data=0001
    // IV=000000000000000000000001
    // AAD=00000000000000000000000000000000000000


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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);

    Crypto_Shutdown();
    free(enc_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}


//16 bytes is max for AES GCM so this is an error test
UTEST(KMC_CRYPTO, UNHAPPY_PATH_APPLY_SEC_ENC_AND_AUTH_AESGCM_32BYTE_MAC)
{
    // Setup & Initialize CryptoLib
    Crypto_Config_CryptoLib(SADB_TYPE_MARIADB, CRYPTOGRAPHY_TYPE_KMCCRYPTO, CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR,
                            TC_IGNORE_SA_STATE_FALSE, TC_IGNORE_ANTI_REPLAY_TRUE, TC_UNIQUE_SA_PER_MAP_ID_FALSE,
                            TC_CHECK_FECF_TRUE, 0x3F, SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_MariaDB("db-itc-kmc.nasa.gov","sadb", 3306,CRYPTO_TRUE,CRYPTO_TRUE, "/certs/ammos-ca-bundle.crt", NULL, CLIENT_CERTIFICATE, CLIENT_CERTIFICATE_KEY, NULL, "root", NULL);
    Crypto_Config_Kmc_Crypto_Service("https", "itc-kmc.nasa.gov", 8443, "crypto-service","/certs/ammos-ca-bundle.crt",NULL, CRYPTO_TRUE, CLIENT_CERTIFICATE, "PEM", CLIENT_CERTIFICATE_KEY, NULL, NULL);
    Crypto_Config_Add_Gvcid_Managed_Parameter(0, 0x002C, 12, TC_HAS_FECF, TC_NO_SEGMENT_HDRS, 1024);
    int32_t status = Crypto_Init();
    ASSERT_EQ(CRYPTO_LIB_SUCCESS, status);

    MDB_DB_RESET();
    
    char* raw_tc_jpl_mmt_scid44_vcid1= "202c3008000001bd37";
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
    if(status != CRYPTO_LIB_SUCCESS)
    {
        Crypto_Shutdown();
    }
    // we expect an InvalidAlgorithmParameterException for macLength of that size.
    ASSERT_EQ(CRYPTOGRAHPY_KMC_CRYPTO_SERVICE_GENERIC_FAILURE, status);

    Crypto_Shutdown();
    free(raw_tc_jpl_mmt_scid44_vcid1_expect);
    free(ptr_enc_frame);
}


UTEST_MAIN();
