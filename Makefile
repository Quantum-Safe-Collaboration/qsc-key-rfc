all: draft-ietf-cfrg-qsckeys.txt draft-ietf-cfrg-qsckeys.html

draft-ietf-cfrg-qsckeys.txt: draft-ietf-cfrg-qsckeys.xml
	xml2rfc --text draft-ietf-cfrg-qsckeys.xml

draft-ietf-cfrg-qsckeys.html: draft-ietf-cfrg-qsckeys.xml
	xml2rfc --html draft-ietf-cfrg-qsckeys.xml
