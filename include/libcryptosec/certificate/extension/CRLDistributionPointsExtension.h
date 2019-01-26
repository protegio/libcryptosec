#ifndef CRLDISTRIBUTIONPOINTSEXTENSION_H_
#define CRLDISTRIBUTIONPOINTSEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/DistributionPoint.h>

class CRLDistributionPointsExtension : public Extension
{
public:
	CRLDistributionPointsExtension();
	CRLDistributionPointsExtension(X509_EXTENSION *ext);
	virtual ~CRLDistributionPointsExtension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void addDistributionPoint(DistributionPoint &distributionPoint);
	std::vector<DistributionPoint> getDistributionPoints();
	X509_EXTENSION* getX509Extension();
protected:
	std::vector<DistributionPoint> distributionPoints;
};

#endif /*CRLDISTRIBUTIONPOINTSEXTENSION_H_*/
