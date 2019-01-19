#include <stdio.h>
#include <gtest/gtest.h>
#include <libcryptosec/init.h>
#include <libcryptosec/MessageDigest.h>
#include <openssl/evp.h>
#include <iostream>

GTEST_API_ int main(int argc, char **argv) {
	libcryptosec::init();
	testing::InitGoogleTest(&argc, argv);
	int ret = RUN_ALL_TESTS();
	libcryptosec::finish();
	return ret;
}

