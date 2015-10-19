OPT = -g -ggdb -O0
CXXFLAGS = -W -Wall -std=c++11 -Wno-deprecated-declarations $(OPT)

.PHONY: all clean
all: masterlock montrehack.flag.nc
clean:
	rm -f masterlock *.o server_public.cc server_public.h version.cc \
			trysecret tryping tryencrypt msieve.dat msieve.log \
			montrehack.flag montrehack.flag.nc masterlock.zip masterlock-src.zip

server.pem:
	openssl ecparam -out $@ -name secp256k1 -genkey

server_public.cc server_public.h: server.pem
	openssl ec -in server.pem -conv_form compressed -noout -text | awk ' \
		BEGIN { \
			print "#include \"server_public.h\""; \
			print ""; \
			print "unsigned char g_server_public_bin[] = {"; \
		} \
		/^[^ ]/ { PUB=0 } \
		PUB && /^ / { \
			SEEN=1; \
			sub("^ *", "0x"); \
			sub(":$$", ","); \
			gsub(":", ", 0x"); \
			print; \
		} \
		/^pub:/ { PUB=1; } \
		END { \
			print "};"; \
			if (!SEEN) exit 1 \
		} \
	' > server_public.cc
	echo "extern unsigned char g_server_public_bin[$$(grep -o '0x' server_public.cc | wc -l)];" > server_public.h

encrypt.o:: secret.h ping.h
masterlock.o:: secret.h encrypt.h
ping.o:: secret.h version.h version.cc
secret.o:: CPPFLAGS += -DSECRET="\"00164378cd7e18088db868185d25b3c4\""
secret.o:: secret.h server_public.h
tryencrypt.o:: encrypt.h secret.h
tryping.o:: secret.h ping.h
trysecret.o:: secret.h

version.cc: *.cc *.h .git/refs/heads/master
	echo "#include \"version.h\"" > version.cc
	echo "const char *kVersion = \"$$(git describe --always --dirty)\";" >> version.cc

trysecret: secret.o server_public.o trysecret.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ -lcrypto -lssl

tryping: secret.o server_public.o version.o ping.o tryping.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ -lcrypto -lssl

tryencrypt: secret.o server_public.o encrypt.o ping.o version.o tryencrypt.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ -lcrypto -lssl

montrehack.flag:
	echo 'Congratulations!\n\nFLAG{rabrsywpuwnbctkwyett}' > $@

montrehack.flag.nc: montrehack.flag tryencrypt
	./tryencrypt

masterlock:: CPPFLAGS = -DRELEASE
masterlock:: OPT = -O3 -s
masterlock: masterlock.o secret.o server_public.o version.o encrypt.o ping.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ -lcrypto -lssl

masterlock.zip:
	$(MAKE) clean montrehack.flag.nc
	rm -f *.o masterlock
	$(MAKE) masterlock
	zip masterlock.zip masterlock montrehack.flag.nc

masterlock-src.zip: assert.h encrypt.cc encrypt.h masterlock.cc ping.cc ping.h secret.cc secret.h server_public.cc server_public.h version.cc version.h montrehack.flag.nc
	zip masterlock-src.zip $^

publish: masterlock-src.zip
	gsutil cp $^ gs://cpatulea/masterlock-src-$$(git describe --always --dirty).zip

try: montrehack.flag masterlock
	./masterlock

bench: trysecret
	./bench.py
