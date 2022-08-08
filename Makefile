#all: draft-uni-qsckeys.txt draft-uni-qsckeys.html
all: draft-uni-qsckeys-kyber.txt draft-uni-qsckeys-kyber.html

#draft-uni-qsckeys.txt: draft-uni-qsckeys.xml
#	xml2rfc --text draft-uni-qsckeys.xml

#draft-uni-qsckeys.html: draft-uni-qsckeys.xml
#	xml2rfc --html draft-uni-qsckeys.xml


draft-uni-qsckeys-kyber.txt: draft-uni-qsckeys-kyber.xml
	xml2rfc --text draft-uni-qsckeys-kyber.xml

draft-uni-qsckeys-kyber.html: draft-uni-qsckeys-kyber.xml
	xml2rfc --html draft-uni-qsckeys-kyber.xml
