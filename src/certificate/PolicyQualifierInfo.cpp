#include <libcryptosec/certificate/PolicyQualifierInfo.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

PolicyQualifierInfo::PolicyQualifierInfo()
{
	this->type = PolicyQualifierInfo::UNDEFINED;
}

PolicyQualifierInfo::PolicyQualifierInfo(const POLICYQUALINFO *policyQualInfo)
{
	THROW_DECODE_ERROR_IF(policyQualInfo == NULL);
	char *data = NULL;

	this->objectIdentifier = ObjectIdentifier((const ASN1_OBJECT*) policyQualInfo->pqualid);
	int nid = this->objectIdentifier.getNid();
	switch (nid) {
		case NID_id_qt_cps:
			this->type = PolicyQualifierInfo::CPS_URI;
			data = (char *) (policyQualInfo->d.cpsuri->data);
			this->cpsUri = std::string(data);
			break;
		case NID_id_qt_unotice:
			this->type = PolicyQualifierInfo::USER_NOTICE;
			this->userNotice = UserNotice(policyQualInfo->d.usernotice);
			break;
		default:
			this->type = PolicyQualifierInfo::UNDEFINED;
	}
}

PolicyQualifierInfo::~PolicyQualifierInfo()
{
}

void PolicyQualifierInfo::setObjectIdentifier(const ObjectIdentifier& objectIdentifier)
{
	this->objectIdentifier = objectIdentifier;
}

const ObjectIdentifier& PolicyQualifierInfo::getObjectIdentifier() const
{
	return this->objectIdentifier;
}

void PolicyQualifierInfo::setCpsUri(const std::string& cpsUri)
{
	THROW_ENCODE_ERROR_IF(cpsUri.empty());
	this->userNotice = UserNotice();
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_id_qt_cps);
	this->cpsUri = cpsUri;
	this->type = PolicyQualifierInfo::CPS_URI;
}

const std::string& PolicyQualifierInfo::getCpsUri() const
{
	return this->cpsUri;
}

void PolicyQualifierInfo::setUserNotice(const UserNotice& userNotice)
{
	this->userNotice = userNotice;
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_id_qt_unotice);
	this->cpsUri = std::string();
	this->type = PolicyQualifierInfo::USER_NOTICE;
}

const UserNotice& PolicyQualifierInfo::getUserNotice() const
{
	return this->userNotice;
}

PolicyQualifierInfo::Type PolicyQualifierInfo::getType() const
{
	return this->type;
}

POLICYQUALINFO* PolicyQualifierInfo::getSslObject() const
{
	POLICYQUALINFO *ret = POLICYQUALINFO_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	switch (this->type) {
		case PolicyQualifierInfo::CPS_URI:
		{
			try {
				ret->pqualid = this->objectIdentifier.getSslObject();
			} catch (...) {
				POLICYQUALINFO_free(ret);
				throw;
			}

			ret->d.cpsuri = ASN1_IA5STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.cpsuri == NULL,
					POLICYQUALINFO_free(ret);
			);

			int rc = ASN1_STRING_set(ret->d.cpsuri, this->cpsUri.c_str(), this->cpsUri.size());
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					POLICYQUALINFO_free(ret);
			);

			break;
		}
		case PolicyQualifierInfo::USER_NOTICE:
			try {
				ret->pqualid = this->objectIdentifier.getSslObject();
				ret->d.usernotice = this->userNotice.getSslObject();
			} catch (...) {
				POLICYQUALINFO_free(ret);
				throw;
			}
			break;
		default:
			break;
	}

	return ret;
}

std::string PolicyQualifierInfo::toXml(const std::string& tab) const
{
	std::string ret;
	ret = tab + "<policyQualifierInfo>\n";
	switch (this->type) {
		case PolicyQualifierInfo::USER_NOTICE:
			ret += this->objectIdentifier.toXml(tab + "\t");
			ret += this->userNotice.toXml(tab + "\t");
			break;
		case PolicyQualifierInfo::CPS_URI:
			ret += this->objectIdentifier.toXml(tab + "\t");
			ret += tab + "\t<cPSuri>" + this->cpsUri + "</cPSuri>\n";
			break;
		default:
			break;
	}
	ret += tab + "</policyQualifierInfo>\n";
	return ret;
}

