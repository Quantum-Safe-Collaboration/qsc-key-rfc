#all: draft-uni-qsckeys.txt draft-uni-qsckeys.html
all: 	draft-uni-qsckeys-kyber-00.txt \
 	draft-uni-qsckeys-kyber-00.html \
	draft-uni-qsckeys-dilithium-00.txt \
	draft-uni-qsckeys-dilithium-00.html \
	draft-uni-qsckeys-falcon-00.txt \
	draft-uni-qsckeys-falcon-00.html \
	draft-uni-qsckeys-sphincsplus-00.txt \
	draft-uni-qsckeys-sphincsplus-00.html 


#draft-uni-qsckeys.txt: draft-uni-qsckeys.xml
#	xml2rfc --text draft-uni-qsckeys.xml

#draft-uni-qsckeys.html: draft-uni-qsckeys.xml
#	xml2rfc --html draft-uni-qsckeys.xml


draft-uni-qsckeys-kyber-00.txt: draft-uni-qsckeys-kyber-00.xml
	xml2rfc --text draft-uni-qsckeys-kyber-00.xml

draft-uni-qsckeys-kyber-00.html: draft-uni-qsckeys-kyber-00.xml
	xml2rfc --html draft-uni-qsckeys-kyber-00.xml


draft-uni-qsckeys-dilithium-01.txt: draft-uni-qsckeys-dilithium-00.xml
	xml2rfc --text draft-uni-qsckeys-dilithium-00.xml

draft-uni-qsckeys-dilithium-01.html: draft-uni-qsckeys-dilithium-00.xml
	xml2rfc --html draft-uni-qsckeys-dilithium-00.xml


draft-uni-qsckeys-falcon-01.txt: draft-uni-qsckeys-falcon-00.xml
	xml2rfc --text draft-uni-qsckeys-falcon-00.xml

draft-uni-qsckeys-falcon-01.html: draft-uni-qsckeys-falcon-00.xml
	xml2rfc --html draft-uni-qsckeys-falcon-00.xml


draft-uni-qsckeys-sphincsplus-01.txt: draft-uni-qsckeys-sphincsplus-00.xml
	xml2rfc --text draft-uni-qsckeys-sphincsplus-00.xml

draft-uni-qsckeys-sphincsplus-01.html: draft-uni-qsckeys-sphincsplus-00.xml
	xml2rfc --html draft-uni-qsckeys-sphincsplus-00.xml
