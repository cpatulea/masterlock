OPT = -g -ggdb -O0
CXXFLAGS = -W -Wall -std=c++11 -Wno-deprecated-declarations $(OPT)

.PHONY: all clean
all: masterlock montrehack.flag.nc
clean:
	rm -f masterlock *.o server_public.cc server_public.h version.cc \
			trysecret tryping tryencrypt msieve.dat msieve.log \
			montrehack.flag montrehack.flag.nc

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
secret.o:: secret.h server_public.h
tryencrypt.o:: encrypt.h secret.h
tryping.o:: secret.h ping.h
trysecret.o:: secret.h

version.cc: *.cc *.h
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

try: montrehack.flag masterlock
	./masterlock

bench: trysecret
	./bench.py
