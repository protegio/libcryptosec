#ifndef ECDSAKEYPAIR_H_
#define ECDSAKEYPAIR_H_

#include <libcryptosec/KeyPair.h>

#include <string>

class EllipticCurve;

/**
 * Representa um par de chaves assimétricas ECDSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas ECDSA
 * que não possui nome ou NID definido no OpenSSL. Par de chaves é gerada através
 * dos parâmetros da curva, enviados em ASN1 (PEM ou DER) ou pela classe EllipticCurve.
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys
 *
 * @see EllipticCurve
 * @see BrainpoolCurveFactory
 */
class ECDSAKeyPair : public KeyPair {

public:

	/**
	 * Cria par por parâmetros informados em DER
	 * TODO
	 */
	ECDSAKeyPair(const ByteArray& derEncoded);

	/**
	 * Cria par por parâmetros informados em PEM
	 * TODO
	 */
	ECDSAKeyPair(const std::string& encoded);

	/**
	 * Cria par por parãmetros informados por um objeto Curve
	 * TODO
	 */
	ECDSAKeyPair(const EllipticCurve & curve);

	ECDSAKeyPair(AsymmetricKey::Curve curve, bool named=true);

	virtual ~ECDSAKeyPair();

	virtual AsymmetricKey::Algorithm getAlgorithm() const;

protected:
	void generateKey(EC_GROUP * group);
	EC_GROUP *createGroup(const EllipticCurve& curve);
	EC_GROUP *createGroup(ByteArray &derEncoded);
};

#endif /* ECDSAKEYPAIR_H_ */
