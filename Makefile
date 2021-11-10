all: draft-uni-qsckeys.txt draft-uni-qsckeys.html

draft-uni-qsckeys.txt: draft-uni-qsckeys.xml
	xml2rfc --text draft-uni-qsckeys.xml

draft-uni-qsckeys.html: draft-uni-qsckeys.xml
	xml2rfc --html draft-uni-qsckeys.xml
