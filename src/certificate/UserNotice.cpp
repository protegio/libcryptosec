#include <libcryptosec/certificate/UserNotice.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/asn1.h>

UserNotice::UserNotice()
{
}

UserNotice::UserNotice(const USERNOTICE *userNotice)
{
	THROW_DECODE_ERROR_IF(userNotice == NULL);

	if (userNotice->exptext != NULL && userNotice->exptext->data != NULL) {
		this->explicitText = std::string((char*) userNotice->exptext->data);
	}

	if (userNotice->noticeref != NULL && userNotice->noticeref->organization != NULL
			&& userNotice->noticeref->organization->data != NULL && userNotice->noticeref->noticenos) {
		this->organization = std::string((char*) userNotice->noticeref->organization->data);
		int num = sk_ASN1_INTEGER_num(userNotice->noticeref->noticenos);
		for (int i = 0; i < num; i++) {
			ASN1_INTEGER *asn1Int = sk_ASN1_INTEGER_value(userNotice->noticeref->noticenos, i);
			THROW_DECODE_ERROR_IF(asn1Int == NULL);
			long sslNoticeNumber = ASN1_INTEGER_get(asn1Int);
			this->noticeNumbers.push_back(sslNoticeNumber);
		}
	}
}

UserNotice::UserNotice(const std::string& organization, const std::vector<long>& noticeNumbers, const std::string& explicitText) :
		organization(organization),
		noticeNumbers(noticeNumbers),
		explicitText(explicitText)
{
}

UserNotice::~UserNotice()
{
}

void UserNotice::setOrganization(const std::string& organization)
{
	this->organization = organization;
}

const std::string& UserNotice::getOrganization() const
{
	return this->organization;
}

void UserNotice::setNoticeNumbers(const std::vector<long>& noticeNumbers)
{
	this->noticeNumbers = noticeNumbers;
}

const std::vector<long>& UserNotice::getNoticeNumbers() const
{
	return this->noticeNumbers;
}

void UserNotice::setNoticeReference(const std::string& organization, const std::vector<long>& noticeNumbers)
{
	this->organization = organization;
	this->noticeNumbers = noticeNumbers;
}

std::pair<std::string, std::vector<long> > UserNotice::getNoticeReference() const
{
	std::pair<std::string, std::vector<long> > ret;
	ret.first = this->organization;
	ret.second = this->noticeNumbers;
	return ret;
}

void UserNotice::setExplicitText(const std::string& explicitText)
{
	this->explicitText = explicitText;
}

const std::string& UserNotice::getExplicitText() const
{
	return this->explicitText;
}

USERNOTICE* UserNotice::getSslObject() const
{
	unsigned int rc;
	USERNOTICE *ret = USERNOTICE_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	if (!this->explicitText.empty()) {
		ret->exptext = ASN1_UTF8STRING_new();
		THROW_ENCODE_ERROR_AND_FREE_IF(ret->exptext == NULL,
				USERNOTICE_free(ret);
		);

		rc = ASN1_STRING_set(ret->exptext, this->explicitText.c_str(), this->explicitText.size());
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				USERNOTICE_free(ret);
		);
	}

	if (!this->organization.empty()) {
		ret->noticeref = NOTICEREF_new();
		THROW_ENCODE_ERROR_AND_FREE_IF(ret->noticeref == NULL,
				USERNOTICE_free(ret);
		);

		ret->noticeref->organization = ASN1_UTF8STRING_new();
		THROW_ENCODE_ERROR_AND_FREE_IF(ret->noticeref->organization == NULL,
				USERNOTICE_free(ret);
		);

		rc = ASN1_STRING_set(ret->noticeref->organization, this->organization.c_str(), this->organization.size());
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				USERNOTICE_free(ret);
		);

		ret->noticeref->noticenos = sk_ASN1_INTEGER_new_null();
		THROW_ENCODE_ERROR_AND_FREE_IF(ret->noticeref->noticenos == NULL,
				USERNOTICE_free(ret);
		);

		for (auto noticeNumber : this->noticeNumbers) {
			ASN1_INTEGER *asn1Int = ASN1_INTEGER_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(asn1Int == NULL,
					USERNOTICE_free(ret);
			);

			rc = ASN1_INTEGER_set(asn1Int, noticeNumber);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					ASN1_INTEGER_free(asn1Int);
					USERNOTICE_free(ret);
			);

			rc = sk_ASN1_INTEGER_push(ret->noticeref->noticenos, asn1Int);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					ASN1_INTEGER_free(asn1Int);
					USERNOTICE_free(ret);
			);
		}
	}

	return ret;
}

std::string UserNotice::toXml(const std::string& tab) const
{
	std::stringstream ss;
	std::string ret;
	std::string ints;
	unsigned int i;
	long value;

	ret = tab + "<userNotice>\n";
	if (!this->organization.empty()) {
		ret += tab + "\t<noticeRef>\n";
			ret += tab + "\t\t<organization>" + this->organization + "</organization>\n";
			ints = "";
			if (this->noticeNumbers.size() > 0) {
				value = this->noticeNumbers.at(0);
				ss << value;
				ints = ss.str();
				for (i = 1; i < this->noticeNumbers.size(); i++) {
					value = this->noticeNumbers.at(i);
					ss.clear();
					ss << value;
					ints += " ";
					ints += ss.str();
				}
			}
			ret += tab + "\t\t<noticeNumbers>" + ints + "</noticeNumbers>\n";
		ret += tab + "\t</noticeRef>\n";
	}

	if (!this->explicitText.empty()) {
		ret += tab + "\t<explicitText>" + this->explicitText + "</explicitText>\n";
	}
	ret += tab + "</userNotice>\n";

	return ret;
}
