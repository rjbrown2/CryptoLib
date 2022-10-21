CREATE USER `root`@`172.28.0.2` REQUIRE SUBJECT '/C=US/ST=WestVirginia/L=Fairmont/O=NASA/OU=ITC_KMC_Container/CN=itc-kmc.nasa.gov/emailAddress=Robert.J.Brown@nasa.gov';
grant all privileges on sadb.* to `root`@`172.28.0.2`;
flush privileges;
CREATE USER `root`@`172.28.0.4` REQUIRE SUBJECT '/C=US/ST=WestVirginia/L=Fairmont/O=NASA/OU=ITC_KMC_Container/CN=redhat-itc-kmc.nasa.gov/emailAddress=Robert.J.Brown@nasa.gov';
grant all privileges on sadb.* to `root`@`172.28.0.4`;
flush privileges;
CREATE USER `root`@`172.28.0.5` REQUIRE SUBJECT '/C=US/ST=WestVirginia/L=Fairmont/O=NASA/OU=ITC_KMC_Container/CN=debian-itc-kmc.nasa.gov/emailAddress=Robert.J.Brown@nasa.gov';
grant all privileges on sadb.* to `root`@`172.28.0.5`;
flush privileges;
