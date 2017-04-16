CXX=$(shell wx-config --cxx)
CXXFLAGS+=-Wall -I/usr/local/include -Wfatal-errors
CXXFLAGS+=$(shell wx-config  --cppflags core,base,gl) -DGLEW_BUILD=GLEW_STATIC
#CXXFLAGS+=-I/usr/include/machine # we need this for <endian.h>?!?!
CXXFLAGS+=-g -O3 # debug me
#CXXFLAGS+=-std=c++11 -stdlib=libc++

LIBS+=$(shell wx-config --libs)
LDFLAGS=$(CXXFLAGS)
TARGET=passmate
SRC=$(wildcard *.cpp)
EECHO=echo
.PHONY: all
all: $(TARGET)
$(TARGET): $(SRC:.cpp=.o)
	@$(EECHO) " \033[34m[LD]\033[0m\t$@"
	@$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.cpp
	@$(EECHO) " \033[33m[CC]\033[0m\t$@"
	@$(CXX) $(CXXFLAGS) -c $< -o $@
%.d: %.cpp
	@$(EECHO) " \033[35m[DP]\033[0m\t$@"
	@set -o errexit; rm -f $@; \
	$(CXX) $(CXXFLAGS) -M $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$
-include $(SRC:.cpp=.d)
.PHONY: clean
clean:
	@$(EECHO) " \033[31m[RM]\033[0m"
	@rm -f $(TARGET) $(SRC:.cpp=.o) $(SRC:.cpp=.d)
# disables implicit rules:
.SUFFIXES: