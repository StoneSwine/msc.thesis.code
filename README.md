# Code

This repository contains the code used in my master thesis - Compact Datastructures in Intrusion detection systems.

clone with: 

```sh
git clone --recursive [URL]

```

## Requirements

* CMake >= 2.6, for the build system
* [Boost](https://www.boost.org/doc/libs/1_66_0/more/getting_started/unix-variants.html) >= 1.42


## Installation
```
# Install the library (Linux or Mac OS X system) - https://github.com/simongog/sdsl-lite/#installation
./sdsl/install.sh $(pwd)
cd ./succinct
cmake .
make
cd ../src
make
```

After installation, the programs can be found in `src/bin/`. 
