#ifndef DATETIME_H_
#define DATETIME_H_

#include <openssl/asn1.h>

#include <time.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

#include "BigInteger.h"

/**
 * @ingroup Util
 */

/**
 * @brief Implementa a representação da data.
 * É utilizada em certificados, LCRs.
 * Utiliza o formato epoch (time_t) para representar datas internamente. 
  */
class DateTime
{
public:
	
	/**
	 * @struct DateVal
	 * Contem dados sobre uma data. Equivalente ao struct tm (time.h)
	 */
	struct DateVal
	{
		  uint32_t sec;			/* Seconds.	[0-60] (1 leap second) */
		  uint32_t min;			/* Minutes.	[0-59] */
		  uint32_t hour;		/* Hours.	[0-23] */
		  uint32_t dayOfMonth;	/* Day.		[1-31] */
		  uint32_t mon;			/* Month.	[0-11] */
		  uint32_t year;		/* Year.	[0-UINT32_MAX] */
		  uint32_t dayOfWeek;	/* Day of week.	[0-6] */
		  uint32_t dayOfYear;	/* Days of year.[0-365]	*/
	};
	
	/**
	 * Construtor padrão.
	 * Cria um objeto DateTime com data 0 (00:00:00 UTC, 1 de Janeiro de 1970).
	 */
	DateTime();
	
	/**
	 * Construtor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param dateTime data específica em segundos.
	 * obs: linux: time_t = __SLONGWORD_TYPE = long int = long.
	 */
	DateTime(time_t dateTime);
	
	/**
	 * Construtor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param dateTime data específica em segundos.
	 */
	DateTime(BigInteger const& dateTime);
	
	/**
	 * Contrutor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param asn1Time data específica. 
	 */	
	DateTime(const ASN1_TIME *asn1Time);

	/**
	 * Contrutor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param utc string no formato UTCTime(YYMMDDHHMMSSZ) ou GeneralizedTime (YYYYMMDDHHMMSSZ).
	 * Notar que ambos estão no fuso Zulu (GMT+0). 
	 */	
	DateTime(std::string utc);
	
	/**
	 * Destrutor.
	 */
	virtual ~DateTime();
	
	/** 
	 * Obtem representação da data em formato Xml
	 * @return data em formato Xml
	 */	
	std::string toXml(const std::string& tab = "") const;

	/**
	 * Define a data do objeto DateTime.
	 * @param dateTime data específica em segundos.
	 */
	void setDateTime(time_t dateTime);

	/**
	 * Define a data do objeto DateTime.
	 * @param dateTime data específica em segundos.
	 */
	void setDateTime(BigInteger const& dateTime);
	
	/**
	 * Obtem data em segundos.
	 * @return data em segundos. 
	 */
	time_t getDateTime() const;
	
	/**
	 * Obtem data em segundos.
	 * @return data em segundos. 
	 */
	BigInteger const& getSeconds() const throw();
	
	/**
	 * Obtem data em formato ASN1.
	 * @return objeto ASN1_TIME no formato UTCTime se ano inferior a 2050, GeneralizedTime caso contrario.
	 */
	ASN1_TIME* getAsn1Time() const;
	
	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato GeneralizedTime (YYYYMMDDHHMMSSZ).
	*/
	ASN1_TIME* getGeneralizedTime() const;
	
	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato UTCTime (YYMMDDHHMMSSZ).
	*/
	ASN1_TIME* getUTCTime() const;
			
	/**
	 * Obtem data em formato ISO8601.
	 * @return string no formato YYYY-MM-DDTHH:MM:SS (no GMT).
	 */
	std::string getISODate() const;
	
	/**
	 * Operador de atribuição.
	 * @param value referência para objeto DateTime.
	 */
	DateTime& operator =(const DateTime& value);
	
	/**
	 * Transforma do formato em segundos (epoch) para ano, mês, dia, hora, minuto e segundo.
	 * @param epoch referência para segundos.
	 * @return estrutura com ano, mês, dia, hora, minuto e segundo.
	 * */
	static DateTime::DateVal getDate(BigInteger const& epoch)
	{
		const long SECS_DAY = 86400L;
		DateTime::DateVal ret;							
		BigInteger yearsSinceEpoch(0L);
		BigInteger leapDays(0L);
		BigInteger daysSinceEpoch(0L);		
		BigInteger tmp;			
		BigInteger hours(epoch);
		BigInteger days(epoch);
		int dayOfYear;
		int sizeOfMonth;
		
		hours.mod(SECS_DAY);
		days.div(SECS_DAY);
		
		tmp = hours % 60;
		ret.sec = tmp.toInt32();
					
		tmp = (hours % 3600).div(60);
		ret.min = tmp.toInt32();
		
		hours.div(3600);
		ret.hour = hours.toInt32();
		
		ret.year = 1970;

		while(days >= DateTime::getYearSize(ret.year))
		{
			days.sub(DateTime::getYearSize(ret.year));
			ret.year++;
		}
		
		ret.dayOfYear = days.toInt32();
		dayOfYear = ret.dayOfYear;
		
		ret.mon = 0;
		sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		while(dayOfYear >= sizeOfMonth)
		{
			dayOfYear-= sizeOfMonth;
			ret.mon++;
			sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		}
		ret.dayOfMonth = dayOfYear + 1;
		
		ret.dayOfWeek = DateTime::getDayOfWeek(ret.year, ret.mon, ret.dayOfMonth);
		
		return ret;
	}
	
	/**
	 * Adiciona segundos.
	 * @param quantidade de segundos.
	 * */	
	void addSeconds(long b);
	
	/**
	 * Adiciona minutos.
	 * @param quantidade de minutos.
	 * */
	void addMinutes(long b);
	
	/**
	 * Adiciona horas.
	 * @param quantidade de horas.
	 * */	
	void addHours(long b);
	
	/**
	 * Adiciona dias.
	 * @param quantidade de dias.
	 * */	
	void addDays(long b);

	/**
	 * Adiciona anos.
	 * @param quantidade de anos.
	 * */	
	void addYears(long b);
	
	/**
	 * Transforma de formato UTCTime(YYMMDDHHMMSSZ) ou GeneralizedTime (YYYYMMDDHHMMSSZ) para epoch(segundos).
	 * @param aString string no formato 'YYMMDDHHMMSSZ' ou 'YYYYMMDDHHMMSSZ'.
	 * return segundos.
	 * */
	static BigInteger date2epoch(std::string aString)
	{
		int year;
		int month; //[0-11]
		int day; //[1-31]
		int hour; //[0-23]
		int min; //[0-59]
		int sec; //[0-59]  + leap second?	
		bool utc = false;
		std::istringstream stream;
		int gtoffset = 0; //deslocamento adicionar para substring se for generalizedtime
		
		utc = aString.size() == 13;
		
		//year
		if(utc)
		{
			stream.str(aString.substr(0,2));
			stream >> year;
			
			if(year >= 50)
			{
				year+= 1900;
			}
			else
			{
				year+= 2000;
			}			
		}
		else //gt
		{
			stream.str(aString.substr(0,4));
			stream >> year;
			gtoffset = 2;
		}
		
		//month
		stream.clear();
		stream.str(aString.substr(2 + gtoffset,2));
		stream >> month;
		month--;
			
		//day
		stream.clear();
		stream.str(aString.substr(4 + gtoffset,2));
		stream >> day;
		
		//hour
		stream.clear();
		stream.str(aString.substr(6 + gtoffset,2));
		stream >> hour;
		
		//min
		stream.clear();
		stream.str(aString.substr(8 + gtoffset,2));
		stream >> min;
		
		//sec
		stream.clear();
		stream.str(aString.substr(10 + gtoffset,2));
		stream >> sec;

		return date2epoch(year, month, day, hour, min, sec);
	}
	
	/**
	 * Transforma do formato ano, mês [0-11], dia [1-31], hora [0-23], minuto [0-59] e segundo [0-59] (Zulu/GMT+0) para epoch.
	 * @return segundos.
	 * */	
	static BigInteger date2epoch(int year, int month, int day, int hour, int min, int sec)
	{
		BigInteger ret(0L);
		
		for(int i = 1970; i < year; i++)
		{
			ret.add(DateTime::getYearSize(i));
		}
		
		for(int i = 0 ; i < month ; i ++)
		{
			ret.add(DateTime::getMonthSize(i, year));
		}
		
		ret.add(day - 1);	
		ret.mul(24);
		ret.add(hour);
		ret.mul(60);
		ret.add(min);
		ret.mul(60);
		ret.add(sec);
			
		return ret;
	}
	
	/***
	 * Retorna o dia da semana dados ano, mês [0-11] e dia [1-31].
	 * @return dia da semana: 0 para Domingo, 6 para Sábado.
	 * obs: code adapted from http://www.sislands.com/coin70/week3/dayofwk.htm
	 * */
	static int getDayOfWeek(int year, int month, int day) throw()
	{
		month++; //para adaptar ao algoritmo
		
		int a = (14 - month) / 12;
		int y = year - a;
		int m = month + 12 * a - 2;    
		return (day + y + (y / 4) - (y / 100) + (y / 400) + ((31 * m) / 12))  % 7;		
	}
	
	/*	static int getDayOfWeek(int year, int month, int day) throw()
	{
		int doomsDays[] = {3, 28, 7, 4, 9, 6, 11, 8, 5, 10, 7, 12};
		int doomsDay;
		int ret = 0;
		int dayOfWeek;
		
		dayOfWeek = DateTime::getDoomsday(year);
		
		doomsDay = doomsDays[month];
		
		if(isLeapYear(year) & ( (month == 0) || (month == 1)) ) //jan and feb
		{
			doomsDay++;
		}
		
		if(day < doomsDay)
		{
			ret = (dayOfWeek - (doomsDay - day)) % 7; 
		}
		else if(day > doomsDay)
		{
			ret = (dayOfWeek + (day - doomsDay)) % 7;
		}
		else
		{
			ret = dayOfWeek;
		}
			
		if(ret < 0)
		{
			ret += 7;
		}
		
		return ret;
	}*/
	
	/**
	 * Retorna dia da semana de referência (doomsday) para um ano específico.
	 * @param year ano.
	 * @return dia da semana: 0 para Domingo, 6 para Sábado.
	 * */
	/*inline static int getDoomsday(int year) throw()  //YYYY
	{
		return (2 + year + (year/4) - (year/100) + (year/400)) % 7;
	}*/
	
	/**
	 * Verifica se um ano é bissexto.
	 * @param y ano.
	 * @return true se é bissexto, false caso contrário.
	 * */
	inline static bool isLeapYear(int y) throw()
	{
		return (y>0) && !(y%4) && ( (y%100) || !(y%400) );
	}

	/**
	 * Retorna quantidade de dias de um ano
	 * @param year ano desejado.
	 * @return número de dias.
	 * */
	inline static int getYearSize(int year)
	{
		int ret = 365;
		
		if(DateTime::isLeapYear(year))
		{
			ret = 366;
		}
		
		return ret;
	}
	
	/**
	 * Retorna quantidade de dias de um ano
	 * @param month mês [0-11]
	 * @param year ano desejado.
	 * @return número de dias.
	 * */
	inline static int getMonthSize(int month, int year)
	{
		int daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
		
		int ret = daysOfMonths[month];
		
		if( (DateTime::isLeapYear(year)) && (month == 1) )
		{
			ret++;
		}
		
		return ret;
	}	
	
	bool operator==(const DateTime& other) const throw();
	bool operator==(time_t other) const;

	bool operator<(const DateTime& other) const throw();
	bool operator<(time_t other) const;

	bool operator>(const DateTime& other) const throw();
	bool operator>(time_t other) const;

		
protected:
	/*
	 * Segundos desde  00:00:00 on January 1, 1970, Coordinated Universal Time (UTC).
	 * */
	BigInteger seconds;
};

#endif /*DATETIME_H_*/
