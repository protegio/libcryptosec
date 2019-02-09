#include <libcryptosec/pkcs7/Pkcs7.h>

#include <openssl/rand.h>

#include <memory.h>

#define BUFFER_SIZE 1024

CertPathValidatorResult Pkcs7::cpvr;

Pkcs7::Pkcs7(PKCS7* pkcs7)
{
	this->pkcs7 = pkcs7;
}

Pkcs7::Pkcs7(const PKCS7* pkcs7) :
		pkcs7(PKCS7_dup((PKCS7*) pkcs7))
{
	THROW_DECODE_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7::Pkcs7(const std::string& pemEncoded)
{
	DECODE_PEM(this->pkcs7, pemEncoded, PEM_read_bio_PKCS7);
}

Pkcs7::Pkcs7(const ByteArray& derEncoded)
{
	DECODE_DER(this->pkcs7, derEncoded, d2i_PKCS7_bio);
}

Pkcs7::Pkcs7(const Pkcs7& pkcs7) :
		pkcs7(PKCS7_dup(pkcs7.pkcs7))
{
	THROW_DECODE_ERROR_IF(this->pkcs7 == NULL);
}

Pkcs7::Pkcs7(Pkcs7&& pkcs7) :
		pkcs7(std::move(pkcs7.pkcs7))
{
	pkcs7.pkcs7 = NULL;
}

Pkcs7::~Pkcs7()
{
	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}
}

Pkcs7& Pkcs7::operator=(const Pkcs7& pkcs7)
{
	if (&pkcs7 == this) {
		return *this;
	}

	PKCS7 *sslObject = PKCS7_dup(pkcs7.pkcs7);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}

	this->pkcs7 = sslObject;

	return *this;
}

Pkcs7& Pkcs7::operator=(Pkcs7&& pkcs7)
{
	if (&pkcs7 == this) {
		return *this;
	}

	if (this->pkcs7 != NULL) {
		PKCS7_free(this->pkcs7);
	}

	this->pkcs7 = pkcs7.pkcs7;
	pkcs7.pkcs7 = NULL;

	return *this;
}

Pkcs7::Type Pkcs7::getType() const
{
	int nid = OBJ_obj2nid(this->pkcs7->type);
	switch (nid) {
	case NID_pkcs7_signed:
		return Pkcs7::Type::SIGNED;
	case NID_pkcs7_enveloped:
		return Pkcs7::Type::ENVELOPED;
	case NID_pkcs7_signedAndEnveloped:
		return Pkcs7::Type::SIGNED_AND_ENVELOPED;
	case NID_pkcs7_encrypted:
		return Pkcs7::Type::ENCRYPTED;
	case NID_pkcs7_digest:
		return Pkcs7::Type::DIGESTED;
	case NID_pkcs7_data:
		return Pkcs7::Type::DATA;
	default:
		THROW_DECODE_ERROR_IF(true);
	}
}

std::string Pkcs7::getPemEncoded() const
{
	ENCODE_PEM_AND_RETURN(this->pkcs7, PEM_write_bio_PKCS7);
}

ByteArray Pkcs7::getDerEncoded() const
{
	ENCODE_DER_AND_RETURN(this->pkcs7, i2d_PKCS7_bio);
}

void Pkcs7::extract(std::ostream& out)
{
	// TODO: não encontramos uma forma padrão de extrair os dados de um PKCS7 do tipo DATA.
	// PKCS7_dataInit e PKCS7_dataFinal aparentemente deveriam funcionar, mas o BIO retornado
	// sempre retorna 0 bytes lidos na chamada BIO_read.
	if (this->getType() == Pkcs7::Type::DATA) {
		out.write((const char*) this->pkcs7->d.data->data, this->pkcs7->d.data->length);
		return;
	}

	BIO *p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	THROW_DECODE_ERROR_IF(p7bio == NULL);

	// TODO: 1KB pode ser muito para um sistema embarcado
	int maxSize = BUFFER_SIZE;
	int size;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0 || size == -1) break;
		out.write(buf, size);
	} while (size == maxSize);

	BIO_free(p7bio);
}

void Pkcs7::decrypt(const Certificate& certificate, const PrivateKey& privateKey, std::ostream& out)
{
	const EVP_PKEY *sslPkey = privateKey.getEvpPkey();
	const X509 *sslCertificate = certificate.getX509();

	// CAST: PKCS7_dataDecode não modifica o certificado
	// CAST: PKCS7_dataDecode não modifica a chave privada
	BIO *p7bio = PKCS7_dataDecode(this->pkcs7, (EVP_PKEY*) sslPkey, NULL, (X509*) sslCertificate);
	THROW_DECODE_ERROR_AND_FREE_IF(p7bio == NULL,
			BIO_free_all(p7bio);
	);

	// TODO: 1KB pode ser muito para sistemas embarcados.
	int maxSize = BUFFER_SIZE;
	int size;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		out.write(buf, size);
	} while (size != 0);

	BIO_free(p7bio);
}

void Pkcs7::decrypt(const SymmetricKey& symmetricKey, std::ostream& out)
{
	const ByteArray& keyData = symmetricKey.getEncoded();
	unsigned int keyDataSize = keyData.getSize() / 8;
	unsigned char *sslKeyData = (unsigned char*) OPENSSL_malloc(keyDataSize);
	THROW_DECODE_ERROR_IF(sslKeyData == NULL);

	memcpy(sslKeyData, keyData.getConstDataPointer(), keyDataSize);

	// decryptInit frees sslKeyData using OPENSSL_clear_free
	BIO *p7bio = this->decryptInit(this->pkcs7, NULL, sslKeyData, keyDataSize);
	THROW_DECODE_ERROR_AND_FREE_IF(p7bio == NULL,
			BIO_free_all(p7bio);
	);

	// TODO: 1KB pode ser muito para sistemas embarcados.
	int maxSize = BUFFER_SIZE;
	int size;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		out.write(buf, size);
	} while (size != 0);

	BIO_free_all(p7bio);
}

bool Pkcs7::verify(
		bool checkSignerCert,
		const vector<Certificate>& trustedCerts,
		CertPathValidatorResult **cpvr,
		const vector<ValidationFlags>& vflags)
{
	bool ret;
	int rc;
	int flags = 0;
	X509_STORE *store = NULL;
	STACK_OF(X509) *certs = NULL;

	// TODO: colocar no init?
	ERR_load_crypto_strings();

	if(checkSignerCert) {
		store = newX509Store(trustedCerts, cpvr, vflags);
	} else {
		flags = PKCS7_NOVERIFY;
	}

	// TODO: add support for detached data
	rc = PKCS7_verify(this->pkcs7, certs, store, NULL, NULL, flags);
	if (rc == 1) {
		ret = true;
	} else {
		// this case can be a error
		ret = false;
		if(cpvr) {
			*cpvr = new CertPathValidatorResult(Pkcs7::cpvr);
		}
	}

	if (store != NULL) {
		X509_STORE_free(store);
	}

	return ret;
}

bool Pkcs7::verifyAndExtract(
		std::ostream& out,
		bool checkSignerCert,
		const vector<Certificate>& trusted,
		CertPathValidatorResult** cpvr,
		const vector<ValidationFlags>& flags)
{
	bool ret = this->verify(checkSignerCert, trusted, cpvr, flags);

	BIO *p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	THROW_DECODE_ERROR_IF(p7bio == NULL);

	int size;
	int maxSize = BUFFER_SIZE;
	char buf[maxSize];

	do {
		// TODO: A documentação do OPENSSL diz que BIO_read pode retornar 0
		// ou -1 para indicar que não há dados para serem lidos AGORA e não
		// necessariamente por causa de um erro. Aqui nós tratamos sempre como
		// fim dos daos e finalizamos a extração. Talvez, o correto fosse verificar
		// se chegou em um null terminator ou algo parecido.
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0 || size == -1) break;
		out.write(buf, size);
	} while (size == maxSize);

	BIO_free(p7bio);

	return ret;
}

bool Pkcs7::verify(
		const Certificate& certificate,
		const PrivateKey& privateKey,
		bool checkSignerCert,
		const std::vector<Certificate>& trustedCerts,
		CertPathValidatorResult **cpvr,
		const std::vector<ValidationFlags>& vflags)
{
	bool ret;
	int rc;
	int flags = 0;
	X509_STORE *store = NULL;
	STACK_OF(X509) *certs = NULL;

	// TODO: colocar no init?
	ERR_load_crypto_strings();

	if(checkSignerCert) {
		store = newX509Store(trustedCerts, cpvr, vflags);
	} else {
		flags = PKCS7_NOVERIFY;
	}

	// TODO: add support for detached data
	rc = this->verify(certificate, privateKey, this->pkcs7, certs, store, NULL, NULL, flags);

	if (rc == 1) {
		ret = true;
	} else {
		// this case can be a error
		ret = false;
		if(cpvr) {
			*cpvr = new CertPathValidatorResult(Pkcs7::cpvr);
		}
	}

	if (store != NULL) {
		X509_STORE_free(store);
	}

	return ret;
}


int Pkcs7::callback(int ok, X509_STORE_CTX *ctx)
{
	if (!ok) {
		const X509* sslCert = X509_STORE_CTX_get_current_cert(ctx);
		if (sslCert != NULL) {
			Certificate *cert = new Certificate(sslCert);
			Pkcs7::cpvr.setInvalidCertificate(cert);
			delete cert;
		}

		int error = X509_STORE_CTX_get_error(ctx);

		int depth = X509_STORE_CTX_get_error_depth(ctx);
		CertPathValidatorResult::ErrorCode errorCode = CertPathValidatorResult::long2ErrorCode(error);

		Pkcs7::cpvr.setDepth(depth);
		Pkcs7::cpvr.setErrorCode(errorCode);

		if (error == X509_V_ERR_CERT_HAS_EXPIRED) ok = 1;

		// since we are just checking the certificates, it is ok
		// if they are self signed. But we should still warn the user
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;

		//Continue after extension errors too
		if (error == X509_V_ERR_INVALID_CA) ok = 1;
		if (error == X509_V_ERR_INVALID_NON_CA) ok = 1;
		if (error == X509_V_ERR_PATH_LENGTH_EXCEEDED) ok = 1;
		if (error == X509_V_ERR_INVALID_PURPOSE) ok = 1;
		if (error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ok = 1;
		if (error == X509_V_ERR_CRL_HAS_EXPIRED) ok = 1;
		if (error == X509_V_ERR_CRL_NOT_YET_VALID) ok = 1;
		if (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ok = 1;
		//TODO incluir informacoes de erro de politicas na classe CertPathValidatorResult
	}

	return ok;
}

std::vector<Certificate> Pkcs7::getCertificates() const
{
	std::vector<Certificate> ret;
	int num = sk_X509_num(this->pkcs7->d.sign->cert);
	for (int i = 0; i < num; i++) {
		const X509 *oneCertificate = sk_X509_value(this->pkcs7->d.sign->cert, i);
		THROW_DECODE_ERROR_IF(oneCertificate == NULL);

		Certificate certificate(oneCertificate);
		ret.push_back(std::move(certificate));
	}
	return ret;
}

std::vector<CertificateRevocationList> Pkcs7::getCrls() const
{
	std::vector<CertificateRevocationList> ret;
	int num = sk_X509_CRL_num(this->pkcs7->d.sign->crl);
	for (int i = 0; i < num; i++) {
		const X509_CRL *oneX509Crl = sk_X509_CRL_value(this->pkcs7->d.sign->crl, i);
		THROW_DECODE_ERROR_IF(oneX509Crl == NULL);
		CertificateRevocationList crl(oneX509Crl);
		ret.push_back(std::move(crl));
	}
	return ret;
}

BIO* Pkcs7::decryptInit(PKCS7 *p7, BIO *in_bio, unsigned char* key, unsigned int keySize) const
{
    int i;
    BIO *out = NULL, *btmp = NULL, *etmp = NULL, *bio = NULL;
    ASN1_OCTET_STRING *data_body = NULL;
    const EVP_CIPHER *evp_cipher = NULL;
    EVP_CIPHER_CTX *evp_ctx = NULL;
    X509_ALGOR *enc_alg = NULL;
    unsigned char *tkey = NULL;
    int tkeylen = 0;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_NO_CONTENT);
        return NULL;
    }

    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    switch (i) {
    case NID_pkcs7_encrypted:
        enc_alg = p7->d.encrypted->enc_data->algorithm;
        /* data_body is NULL if the optional EncryptedContent is missing. */
        data_body = p7->d.encrypted->enc_data->enc_data;
        evp_cipher = EVP_get_cipherbyobj(enc_alg->algorithm);
        if (evp_cipher == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE,
                     PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
            goto err;
        }
        break;
    default:
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
        goto err;
    }

    /* Detached content must be supplied via in_bio instead. */
    if (data_body == NULL && in_bio == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATADECODE, PKCS7_R_NO_CONTENT);
        goto err;
    }

    if (evp_cipher != NULL) {
        if ((etmp = BIO_new(BIO_f_cipher())) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_BIO_LIB);
            goto err;
        }

        evp_ctx = NULL;
        BIO_get_cipher_ctx(etmp, &evp_ctx);
        if (EVP_CipherInit_ex(evp_ctx, evp_cipher, NULL, NULL, NULL, 0) <= 0)
            goto err;

        if (EVP_CIPHER_asn1_to_param(evp_ctx, enc_alg->parameter) < 0)
            goto err;

        /* Generate random key as MMA defence */
        tkeylen = EVP_CIPHER_CTX_key_length(evp_ctx);
        tkey = (unsigned char*) OPENSSL_malloc(tkeylen);

        if (tkey == NULL)
            goto err;

        if (EVP_CIPHER_CTX_rand_key(evp_ctx, tkey) <= 0)
            goto err;

        if (key == NULL) {
            key = tkey;
            keySize = tkeylen;
            tkey = NULL;
        }

        if (keySize != EVP_CIPHER_CTX_key_length(evp_ctx)) {
            /*
             * Some S/MIME clients don't use the same key and effective key
             * length. The key length is determined by the size of the
             * decrypted RSA key.
             */
            if (!EVP_CIPHER_CTX_set_key_length(evp_ctx, keySize)) {
                /* Use random key as MMA defence */
                OPENSSL_clear_free(key, keySize);
                key = tkey;
                keySize = tkeylen;
                tkey = NULL;
            }
        }

        /* Clear errors so we don't leak information useful in MMA */
        ERR_clear_error();
        if (EVP_CipherInit_ex(evp_ctx, NULL, NULL, key, NULL, 0) <= 0)
            goto err;

        OPENSSL_clear_free(key, keySize);
        key = NULL;

        OPENSSL_clear_free(tkey, tkeylen);
        tkey = NULL;

        if (out == NULL)
            out = etmp;
        else
            BIO_push(out, etmp);
        etmp = NULL;
    }

    if (in_bio != NULL) {
        bio = in_bio;
    } else {
        if (data_body->length > 0)
            bio = BIO_new_mem_buf(data_body->data, data_body->length);
        else {
            bio = BIO_new(BIO_s_mem());
            if (bio == NULL)
                goto err;
            BIO_set_mem_eof_return(bio, 0);
        }
        if (bio == NULL)
            goto err;
    }

    BIO_push(out, bio);
    bio = NULL;
    return out;

 err:
    OPENSSL_clear_free(key, keySize);
    OPENSSL_clear_free(tkey, tkeylen);
    BIO_free_all(out);
    BIO_free_all(btmp);
    BIO_free_all(etmp);
    BIO_free_all(bio);
    return NULL;
}

int Pkcs7::verify(const Certificate& certificate, const PrivateKey& privateKey,
		PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
		BIO *indata, BIO *out, int flags) const
{
    STACK_OF(X509) *signers;
    X509 *signer;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    X509_STORE_CTX *cert_ctx = NULL;
    char *buf = NULL;
    int i, j = 0, k, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (PKCS7_get_detached(p7) && !indata) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_NO_CONTENT);
        return 0;
    }

    if (flags & PKCS7_NO_DUAL_CONTENT) {
        /*
         * This was originally "#if 0" because we thought that only old broken
         * Netscape did this.  It turns out that Authenticode uses this kind
         * of "extended" PKCS7 format, and things like UEFI secure boot and
         * tools like osslsigncode need it.  In Authenticode the verification
         * process is different, but the existing PKCs7 verification works.
         */
        if (!PKCS7_get_detached(p7) && indata) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_CONTENT_AND_DATA_PRESENT);
            return 0;
        }
    }

    sinfos = PKCS7_get_signer_info(p7);

    if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos)) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_NO_SIGNATURES_ON_DATA);
        return 0;
    }

    signers = this->getSigners(p7, certs, flags);
    if (!signers)
        return 0;

    /* Now verify the certificates */

    STACK_OF(X509) *internalCerts = NULL;
    STACK_OF(X509_CRL) *internalCrls = NULL;

    if (PKCS7_type_is_signed(p7)) {
    	internalCerts = p7->d.sign->cert;
    	internalCrls = p7->d.sign->crl;
    } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
    	internalCerts = p7->d.signed_and_enveloped->cert;
    	internalCrls = p7->d.signed_and_enveloped->crl;
    }

    cert_ctx = X509_STORE_CTX_new();
    if (cert_ctx == NULL)
        goto err;

    if (!(flags & PKCS7_NOVERIFY))
        for (k = 0; k < sk_X509_num(signers); k++) {
            signer = sk_X509_value(signers, k);
            if (!(flags & PKCS7_NOCHAIN)) {
                if (!X509_STORE_CTX_init(cert_ctx, store, signer, internalCerts)) {
                    PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
                    goto err;
                }
                X509_STORE_CTX_set_default(cert_ctx, "smime_sign");
            } else if (!X509_STORE_CTX_init(cert_ctx, store, signer, NULL)) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_X509_LIB);
                goto err;
            }
            if (!(flags & PKCS7_NOCRL))
                X509_STORE_CTX_set0_crls(cert_ctx, internalCrls);
            i = X509_verify_cert(cert_ctx);
            if (i <= 0)
                j = X509_STORE_CTX_get_error(cert_ctx);
            X509_STORE_CTX_cleanup(cert_ctx);
            if (i <= 0) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY,
                         PKCS7_R_CERTIFICATE_VERIFY_ERROR);
                ERR_add_error_data(2, "Verify error:",
                                   X509_verify_cert_error_string(j));
                goto err;
            }
            /* Check for revocation status here */
        }

    /*
     * Performance optimization: if the content is a memory BIO then store
     * its contents in a temporary read only memory BIO. This avoids
     * potentially large numbers of slow copies of data which will occur when
     * reading from a read write memory BIO when signatures are calculated.
     */

    if (indata && (BIO_method_type(indata) == BIO_TYPE_MEM)) {
        char *ptr;
        long len;
        len = BIO_get_mem_data(indata, &ptr);
        tmpin = BIO_new_mem_buf(ptr, len);
        if (tmpin == NULL) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        tmpin = indata;

    if (PKCS7_type_is_signed(p7)) {
		p7bio = PKCS7_dataInit(p7, tmpin);
		if (p7bio == NULL) {
			goto err;
		}
    } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
    	const X509 *pcert = certificate.getX509();
    	const EVP_PKEY *pkey = privateKey.getEvpPkey();
    	p7bio = PKCS7_dataDecode(p7, (EVP_PKEY*) pkey, tmpin, (X509*) pcert);
    }

    if (flags & PKCS7_TEXT) {
        if ((tmpout = BIO_new(BIO_s_mem())) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    if ((buf = (char*) OPENSSL_malloc(BUFFER_SIZE)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(p7bio, buf, BUFFER_SIZE);
        if (i <= 0)
            break;
        if (tmpout)
            BIO_write(tmpout, buf, i);
    }

    if (flags & PKCS7_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_SMIME_TEXT_ERROR);
            BIO_free(tmpout);
            goto err;
        }
        BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & PKCS7_NOSIGS))
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
            signer = sk_X509_value(signers, i);
            j = PKCS7_signatureVerify(p7bio, p7, si, signer);
            if (j <= 0) {
                PKCS7err(PKCS7_F_PKCS7_VERIFY, PKCS7_R_SIGNATURE_FAILURE);
                goto err;
            }
        }

    ret = 1;

 err:
    X509_STORE_CTX_free(cert_ctx);
    OPENSSL_free(buf);
    if (tmpin == indata) {
        if (indata)
            BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    return ret;
}

X509_STORE* Pkcs7::newX509Store(
		const std::vector<Certificate>& trusted,
		CertPathValidatorResult **cpvr,
		const std::vector<ValidationFlags>& flags)
{
	int rc;
	X509_STORE *store = NULL;

	// TODO: colocar no init?
	ERR_load_crypto_strings();

	// instancia store de certificados
	store = X509_STORE_new();
	THROW_DECODE_ERROR_IF(store == NULL);

	// define funcao de callback
	X509_STORE_set_verify_cb_func(store, Pkcs7::callback);

	// define certificados confiaveis
	for(auto certificate : trusted) {
		const X509 *sslCert = certificate.getX509();
		// CAST: X509_STORE_add_cert não modifica sslCert
		rc = X509_STORE_add_cert(store, (X509*) sslCert);
		THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
				X509_STORE_free(store);
		);
	}

	//define flags
	for(auto vflag : flags) {
		switch(vflag) {
			case CRL_CHECK:
				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
				);
				break;

			case CRL_CHECK_ALL:
				/*precisa por CRL_CHECK tambem, caso contrario o openssl nao verifica CRL*/
				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
				THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
				);

				rc = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
				THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
						X509_STORE_free(store);
				);
				break;
		}
	}

	return store;
}

STACK_OF(X509)* Pkcs7::getSigners(PKCS7* p7, STACK_OF(X509)* certs, int flags) const
{
    STACK_OF(X509) *signers;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    PKCS7_ISSUER_AND_SERIAL *ias;
    X509 *signer;
    int i;

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (!PKCS7_type_is_signed(p7) && !PKCS7_type_is_signedAndEnveloped(p7)) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_WRONG_CONTENT_TYPE);
        return NULL;
    }

    /* Collect all the signers together */

    sinfos = PKCS7_get_signer_info(p7);

    if (sk_PKCS7_SIGNER_INFO_num(sinfos) <= 0) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_NO_SIGNERS);
        return 0;
    }

    if ((signers = sk_X509_new_null()) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    STACK_OF(X509) *internalCerts = NULL;

    if (PKCS7_type_is_signed(p7)) {
    	internalCerts = p7->d.sign->cert;
    } else if (PKCS7_type_is_signedAndEnveloped(p7)) {
    	internalCerts = p7->d.signed_and_enveloped->cert;
    }

    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        ias = si->issuer_and_serial;
        signer = NULL;
        /* If any certificates passed they take priority */
        if (certs)
            signer = X509_find_by_issuer_and_serial(certs,
                                                    ias->issuer, ias->serial);
        if (!signer && !(flags & PKCS7_NOINTERN)
            && internalCerts)
            signer =
                X509_find_by_issuer_and_serial(internalCerts,
                                               ias->issuer, ias->serial);
        if (!signer) {
            PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS,
                     PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND);
            sk_X509_free(signers);
            return 0;
        }

        if (!sk_X509_push(signers, signer)) {
            sk_X509_free(signers);
            return NULL;
        }
    }
    return signers;
}

