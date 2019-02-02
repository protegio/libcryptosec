#include <libcryptosec/certificate/DistributionPoint.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

DistributionPoint::DistributionPoint()
{
	for (int i = 0; i < 7; i++) {
		this->reasons[i] = false;
	}
}

DistributionPoint::DistributionPoint(const DIST_POINT *distPoint)
{
	THROW_DECODE_ERROR_IF(distPoint == NULL);

	if (distPoint->distpoint) {
		this->distributionPointName = DistributionPointName(distPoint->distpoint);
	}

	if (distPoint->reasons) {
		for (int i = 0; i < 7; i++) {
			this->reasons[i] = (ASN1_BIT_STRING_get_bit(distPoint->reasons, i)) ? true : false;
		}
	} else {
		for (int i = 0; i< 7; i++) {
			this->reasons[i] = false;
		}
	}

	if (distPoint->CRLissuer) {
		this->crlIssuer = GeneralNames(distPoint->CRLissuer);
	}
}

DistributionPoint::~DistributionPoint()
{
}

void DistributionPoint::setDistributionPointName(const DistributionPointName& dpn)
{
	this->distributionPointName = dpn;
}

const DistributionPointName& DistributionPoint::getDistributionPointName() const
{
	return this->distributionPointName;
}

void DistributionPoint::setReasonFlag(DistributionPoint::ReasonFlags reason, bool value)
{
	this->reasons[reason] = value;
}

bool DistributionPoint::getReasonFlag(DistributionPoint::ReasonFlags reason) const
{
	return this->reasons[reason];
}

void DistributionPoint::setCrlIssuer(const GeneralNames& crlIssuer)
{
	this->crlIssuer = crlIssuer;
}

const GeneralNames& DistributionPoint::getCrlIssuer() const
{
	return this->crlIssuer;
}

std::string DistributionPoint::toXml(const std::string& tab) const
{
	std::string ret, string, reasonValue;
	int i;

	ret = tab + "<distributionPoint>\n";
	if (this->distributionPointName.getType() != DistributionPointName::UNDEFINED) {
		ret += this->distributionPointName.toXml(tab + "\t");
	}

	ret += tab + "\t<reasonFlag>\n";
	for (i = 0; i < 7; i++) {
		string = reasonFlag2Name((DistributionPoint::ReasonFlags) i);
		reasonValue = this->reasons[i] ? "1" : "0";
		ret += tab + "\t\t<"+ string +">" + reasonValue + "</" + string + ">\n";
	}
	ret += tab + "\t</reasonFlag>\n";

	if (this->crlIssuer.getNumberOfEntries() > 0) {
		ret += this->crlIssuer.toXml(tab + "\t");
	}
	ret += tab + "</distributionPoint>\n";

	return ret;
}

DIST_POINT* DistributionPoint::getSslObject() const
{
	DIST_POINT *ret = DIST_POINT_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	if (this->distributionPointName.getType() != DistributionPointName::UNDEFINED) {
		try {
			ret->distpoint = this->distributionPointName.getSslObject();
		} catch (...) {
			DIST_POINT_free(ret);
			throw;
		}
	}

	bool anyReasons = false;
	int i = 0;
	while (!anyReasons && i < 7) {
		if (this->reasons[i]) {
			anyReasons = true;
		}
		i++;
	}

	if (anyReasons) {
		ret->reasons = ASN1_BIT_STRING_new();
		THROW_DECODE_ERROR_AND_FREE_IF(ret->reasons == NULL,
				DIST_POINT_free(ret);
		);

		for (i = 0; i < 7; i++) {
			int rc = ASN1_BIT_STRING_set_bit(ret->reasons, i, this->reasons[i] ? 1 : 0);
			THROW_DECODE_ERROR_AND_FREE_IF(rc == 0,
					DIST_POINT_free(ret);
			);
		}
	}

	if (this->crlIssuer.getNumberOfEntries() > 0) {
		try {
			ret->CRLissuer = this->crlIssuer.getSslObject();
		} catch (...) {
			DIST_POINT_free(ret);
			throw;
		}
	}

	return ret;
}

std::string DistributionPoint::reasonFlag2Name(DistributionPoint::ReasonFlags reason)
{
	std::string ret;
	switch (reason)
	{
		case DistributionPoint::UNUSED:
			ret = "unused";
			break;
		case DistributionPoint::KEY_COMPROMISE:
			ret = "keyCompromise";
			break;
		case DistributionPoint::CA_COMPROMISE:
			ret = "caCompromise";
			break;
		case DistributionPoint::AFFILIATION_CHANGED:
			ret = "affiliationChanged";
			break;
		case DistributionPoint::SUPERSEDED:
			ret = "superseded";
			break;
		case DistributionPoint::CESSATION_OF_OPERATION:
			ret = "cessationOfOperation";
			break;
		case DistributionPoint::CERTIFICATE_HOLD:
			ret = "certificateHold";
			break;
	}
	return ret;
}
