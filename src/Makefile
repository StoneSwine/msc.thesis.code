include ../Make.helper
BINDIR := bin
INCDIR := helper
CXX_FLAGS := $(MY_CXX_FLAGS) $(MY_CXX_OPT_FLAGS) -I $(SUCCINC_DIR) -I$(INC_DIR) -L$(LIB_DIR) -I $(INCDIR)
CCLIB := -lsdsl -ldivsufsort -ldivsufsort64
SOURCES := $(wildcard *.cpp)
EXECS := $(SOURCES:.cpp=.x)

all: $(EXECS)

%.x:%.cpp
	mkdir -p $(BINDIR)
	$(MY_CXX) $(CXX_FLAGS) -o $(BINDIR)/$@ $< $(CCLIB) $(shell find ./$(INCDIR) -type f -name '*.cpp')
	chmod +x $(BINDIR)/$@

clean:
	rm -f $(BINDIR)/*
	rm -rf *.dSYM

