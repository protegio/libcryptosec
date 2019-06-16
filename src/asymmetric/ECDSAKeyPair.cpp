#include <libcryptosec/asymmetric/ECDSAKeyPair.h>

#include <libcryptosec/ec/EllipticCurve.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/ByteArray.h>

#include <libcryptosec/exception/AsymmetricKeyException.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

ECDSAKeyPair::ECDSAKeyPair(const ByteArray& derEncoded) {
	this->key = NULL;
	this->engine = NULL;
	EC_GROUP * group = createGroup(derEncoded);
	generateKey(group);
	EC_GROUP_free(group);
}

ECDSAKeyPair::ECDSAKeyPair(const std::string& encoded) {
	this->key = NULL;
	this->engine = NULL;
	ByteArray derEncoded = Base64::decode(encoded);
	EC_GROUP * group = createGroup(derEncoded);
	generateKey(group);
	EC_GROUP_free(group);
}

ECDSAKeyPair::ECDSAKeyPair(const EllipticCurve & curve) {
	this->key = NULL;
	this->engine = NULL;
	EC_GROUP * group = createGroup(curve);
	generateKey(group);
	EC_GROUP_free(group);
}

ECDSAKeyPair::ECDSAKeyPair(AsymmetricKey::Curve curve, bool named) {
	EC_KEY *eckey;
	this->key = NULL;
	this->engine = NULL;
	eckey = NULL;
	eckey = EC_KEY_new_by_curve_name(curve);

	if (!eckey) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"ECDSAKeyPair::ECDSAKeyPair");
	}
	
	if (named)
		EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_generate_key(eckey);
	
	this->key = EVP_PKEY_new();
	if (!this->key) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"ECDSAKeyPair::ECDSAKeyPair");
	}

	EVP_PKEY_assign_EC_KEY(this->key, eckey);
	if (!this->key) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"ECDSAKeyPair::ECDSAKeyPair");
	}
}

ECDSAKeyPair::~ECDSAKeyPair() {
}

void ECDSAKeyPair::generateKey(EC_GROUP * group)
{
	EC_KEY* eckey = EC_KEY_new();

	if (eckey == NULL){
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed initiate EC_KEY", "ECDSAKeyPair::generateKey");
	}

	//assert (need_rand);??

	if (EC_KEY_set_group(eckey, group) == 0){
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to set group", "ECDSAKeyPair::generateKey");
	}

	if (!EC_KEY_generate_key(eckey)) {
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to generate keys", "ECDSAKeyPair::generateKey");
	}

	if (!eckey) {
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to generate keys", "ECDSAKeyPair::generateKey");
	}

	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(this->key, eckey);
	if (!this->key) {
		EC_KEY_free(eckey);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to assert EC_KEY into EVP_KEY", "ECDSAKeyPair::generateKey");
	}

}

EC_GROUP * ECDSAKeyPair::createGroup(const EllipticCurve& curve) {
	BN_CTX *ctx;
	EC_GROUP *group;
	EC_POINT *generator;

	/* Set up the BN_CTX */
	ctx = BN_CTX_new();
	if (ctx == NULL){
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to create BN_CTX", "ECDSAKeyPair::createGroup");
	}

	/* Create the curve */
	group = EC_GROUP_new_curve_GFp(curve.BN_p(), curve.BN_a(),	curve.BN_b(), ctx);
	if (group == NULL) {
		BN_CTX_free(ctx);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to create group", "ECDSAKeyPair::createGroup");
	}

	/* Create the generator */
	generator = EC_POINT_new(group);
	if (generator == NULL) {
		BN_CTX_free(ctx);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to create generator", "ECDSAKeyPair::createGroup");
	}

	if (1 != EC_POINT_set_affine_coordinates_GFp(group, generator, curve.BN_x(), curve.BN_y(), ctx)) {
		BN_CTX_free(ctx);
		EC_GROUP_free(group);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to set the affine coordinates of a EC_POINT over GFp",
				"ECDSAKeyPair::createGroup");
	}

	/* Set the generator and the order */
	if (1 != EC_GROUP_set_generator(group, generator, curve.BN_order(),	curve.BN_cofactor())) {
		BN_CTX_free(ctx);
		EC_GROUP_free(group);
		EC_POINT_free(generator);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to set generator and order", "ECDSAKeyPair::createGroup");
	}

	EC_POINT_free(generator);
	BN_CTX_free(ctx);

	return group;
}


EC_GROUP * ECDSAKeyPair::createGroup(ByteArray &derEncoded) {
	this->key = NULL;
	this->engine = NULL;
	EC_GROUP *group = NULL;
	BIO * in;

	in = BIO_new_mem_buf(derEncoded.getDataPointer(), derEncoded.getSize());

	if ((in == NULL)) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
						"Failed to initiate BIO", "ECDSAKeyPair::createGroup");
	}

	group = d2i_ECPKParameters_bio(in, NULL);
	if(group == NULL){
		BIO_free(in);
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"Failed to create group", "ECDSAKeyPair::createGroup");
	}

	BIO_free(in);

	return group;
}

AsymmetricKey::Algorithm ECDSAKeyPair::getAlgorithm() const {
	return AsymmetricKey::EC;
}