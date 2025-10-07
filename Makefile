#PROD=no

# Detect the operating system
UNAME_S := $(shell uname -s)

# Set compiler and flags based on OS
ifeq ($(UNAME_S),Darwin)
    # macOS configuration
    CXX = g++
    CXXFLAGS = -Wall -I mbedtls/include/ -Os -s -Lmbedtls/library/ -Wl,-force_load,mbedtls/library/libmbedcrypto.a -Wl,-force_load,mbedtls/library/libmbedtls.a -Wl,-force_load,mbedtls/library/libmbedx509.a -std=c++11
    CFLAGS_MBEDTLS="-s -Os"
else
    # Linux configuration (default)
    CXX = musl-g++
    CXXFLAGS = -Wall -I mbedtls/include/ -Os -s -static -Lmbedtls/library/ -Wl,--start-group -lmbedcrypto -lmbedtls -lmbedx509 -Wl,--end-group -std=c++11
    CFLAGS_MBEDTLS="-s -Os"
    
    # Fallback to regular g++ if musl-g++ is not available
    ifeq (, $(shell which musl-g++))
        CXX = g++
        CXXFLAGS = -Wall -I mbedtls/include/ -Os -Lmbedtls/library/ -Wl,--start-group -lmbedcrypto -lmbedtls -lmbedx509 -Wl,--end-group -std=c++11
    endif
endif

BIN=cb
MCB_BIN=mcb-cpp
.PHONY: mbedtls

all: mbedtls cb mcb-cpp

mbedtls:
	cp -f mbedtls_config.h mbedtls/include/mbedtls/mbedtls_config.h
	CC=gcc CFLAGS=$(CFLAGS_MBEDTLS) make -C mbedtls no_test

cb:
	$(CXX) cb.cpp $(CXXFLAGS) -o $(BIN)

mcb-cpp:
	$(CXX) mcb.cpp $(CXXFLAGS) -lpthread -o $(MCB_BIN)

clean:
	rm -f $(BIN) $(MCB_BIN)
	make -C mbedtls clean

# Add a help target
help:
	@echo "Available targets:"
	@echo "  all       - Build mbedtls, cb, and mcb-cpp (default)"
	@echo "  mbedtls   - Build only mbedtls library"
	@echo "  cb        - Build only cb executable"
	@echo "  mcb-cpp   - Build only mcb-cpp server executable"
	@echo "  clean     - Clean build artifacts"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Detected OS: $(UNAME_S)"
	@echo "Compiler: $(CXX)"