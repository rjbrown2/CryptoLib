CREATE USER `testuser`@`172.28.0.2` REQUIRE SUBJECT '/C=US/ST=WestVirginia/L=Fairmont/O=NASA/OU=ITC_KMC_Container/CN=itc-kmc.nasa.gov/emailAddress=Robert.J.Brown@nasa.gov';
grant all privileges on sadb.* to `testuser`@`172.28.0.2`;
flush privileges;

