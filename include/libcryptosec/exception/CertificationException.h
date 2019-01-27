#ifndef CERTIFICATIONEXCEPTION_H_
#define CERTIFICATIONEXCEPTION_H_

#include <libcryptosec/exception/LibCryptoSecException.h>

class CertificationException : public LibCryptoSecException
{
public:
	enum ErrorCode
	{
		UNKNOWN,
		INVALID_CERTIFICATE,
		INVALID_CRL,
		INVALID_EXTENSION,
		INVALID_RDN_SEQUENCE,
		INVALID_PUBLIC_KEY,
		SET_NO_VALUE,
		INTERNAL_ERROR,
		UNSUPPORTED_ASYMMETRIC_KEY_TYPE,
		INVALID_TYPE,
		ADDING_EXTENSION,
		UNKNOWN_OID,
		KNOWN_OID,
		OBJ_DUP_ERROR,
		SK_TYPE_NEW_NULL_ERROR,
		SK_TYPE_PUSH_ERROR,
		X509V3_EXT_I2D_ERROR,
		X509V3_EXT_D2I_ERROR,
		X509_CRL_NEW_ERROR,
		X509_CRL_DUP_ERROR,
		X509_CRL_SET_VERSION_ERROR,
		X509_CRL_GET_ISSUER_ERROR,
		ENCODE_ERROR,
		DECODE_ERROR
	};
    CertificationException(const std::string& where)
    {
    	this->where = where;
    	this->errorCode = CertificationException::UNKNOWN;
    }
    CertificationException(CertificationException::ErrorCode errorCode, const std::string& where)
    {
    	this->where = where;
    	this->errorCode = errorCode;
    }
	virtual ~CertificationException() throw () {}
	virtual std::string getMessage() const
	{
		return CertificationException::errorCode2Message(this->errorCode);
	}
    virtual std::string toString() const
    {
    	std::string ret;
    	if (this->errorCode == CertificationException::UNKNOWN)
    	{
    		ret = "CertificationException. Called by: " + this->where + ".";
    	}
    	else
    	{
    		ret = "CertificationException: " + CertificationException::errorCode2Message(this->errorCode) + ". Called by: " + this->where + ".";
    	}
    	return ret;
    }
    virtual CertificationException::ErrorCode getErrorCode()
    {
    	return this->errorCode;
    }
    static std::string errorCode2Message(CertificationException::ErrorCode errorCode)
    {
    	std::string ret;
    	switch (errorCode)
    	{
    		case CertificationException::UNKNOWN:
    			ret = "Unknown error";
    			break;
    		case CertificationException::INVALID_CERTIFICATE:
    			ret = "Invalid certificate object";
    			break;
    		case CertificationException::INVALID_CRL:
    			ret = "Invalid CRL object";
    			break;
    		case CertificationException::INVALID_RDN_SEQUENCE:
    			ret = "Invalid RDN Sequence";
    			break;
    		case CertificationException::INVALID_PUBLIC_KEY:
    			ret = "Invalid public key";
    			break;
    		case CertificationException::INVALID_EXTENSION:
    			ret = "Invalid extension";
    			break;
    		case CertificationException::SET_NO_VALUE:
    			ret = "Set no value";
    			break;
    		case CertificationException::INTERNAL_ERROR:
    			ret = "Internal error";
    			break;
    		case CertificationException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE:
    			ret = "Unsupported asymmetric key type";
    			break;
    		case CertificationException::INVALID_TYPE:
    			ret = "Invalid type";
    			break;
    		case CertificationException::ADDING_EXTENSION:
    			ret = "Adding extension";
    			break;
    		case CertificationException::UNKNOWN_OID:
    			ret = "Unknown OID";
    			break;
    		case CertificationException::KNOWN_OID:
    			ret = "Known OID";
    			break;
    		case CertificationException::OBJ_DUP_ERROR:
    			ret = "Object duplication error";
    			break;
    		case CertificationException::SK_TYPE_NEW_NULL_ERROR:
    			ret = "Stack new null error";
    			break;
    		case CertificationException::SK_TYPE_PUSH_ERROR:
    			ret = "Stack push error";
    			break;
    		case CertificationException::X509V3_EXT_I2D_ERROR:
    			ret = "X509v3 extension encode error";
    			break;
    		case CertificationException::X509V3_EXT_D2I_ERROR:
    			ret = "X509v3 extension decode error";
    			break;
    		case X509_CRL_NEW_ERROR:
    			ret = "X509 CRL new error";
    			break;
    		case X509_CRL_DUP_ERROR:
    			ret = "X509 CRL duplication error";
    			break;
    		case X509_CRL_SET_VERSION_ERROR:
    			ret = "X509 CRL set version error";
    			break;
    		case X509_CRL_GET_ISSUER_ERROR:
    			ret = "X509 CRL get issuer error";
    			break;
    		case ENCODE_ERROR:
    			ret = "Encode error";
    			break;
    		case DECODE_ERROR:
    			ret = "Decode Error";
    			break;
    	}
    	return ret;
    }
    
protected:
	CertificationException::ErrorCode errorCode;
};

#endif /*CERTIFICATIONEXCEPTION_H_*/
