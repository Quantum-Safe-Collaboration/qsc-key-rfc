# qsc-key-rfc
collborative environment for developing a QS key serialization document / RFC

Use the Makfefile to build the documents

Pre-requisites:  xml2rfc


draft-uni-qsckeys-kyber-01.txt: draft-uni-qsckeys-kyber-01.xml
	xml2rfc --text draft-uni-qsckeys-kyber-01.xml

draft-uni-qsckeys-kyber-01.html: draft-uni-qsckeys-kyber-01.xml
	xml2rfc --html draft-uni-qsckeys-kyber-01.xml


draft-uni-qsckeys-dilithium-01.txt: draft-uni-qsckeys-dilithium-01.xml
	xml2rfc --text draft-uni-qsckeys-dilithium-01.xml

draft-uni-qsckeys-dilithium-01.html: draft-uni-qsckeys-dilithium-01.xml
	xml2rfc --html draft-uni-qsckeys-dilithium-01.xml


draft-uni-qsckeys-falcon-01.txt: draft-uni-qsckeys-falcon-01.xml
	xml2rfc --text draft-uni-qsckeys-falcon-01.xml

draft-uni-qsckeys-falcon-01.html: draft-uni-qsckeys-falcon-01.xml
	xml2rfc --html draft-uni-qsckeys-falcon-01.xml


draft-uni-qsckeys-sphincsplus-01.txt: draft-uni-qsckeys-sphincsplus-01.xml
	xml2rfc --text draft-uni-qsckeys-sphincsplus-01.xml

draft-uni-qsckeys-sphincsplus-01.html: draft-uni-qsckeys-sphincsplus-01.xml
	xml2rfc --html draft-uni-qsckeys-sphincsplus-01.xml
