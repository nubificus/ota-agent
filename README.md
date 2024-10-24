# Update

Based on Goole opendice
https://github.com/google/open-dice

Copy the files below to update

## Copy to src/
clear_memory.c
dice.c
mbedtls_ops.c
utils.c

## Copy to include/dice/
config.h
dice.h
ops.h
utils.h

# Compile

- ```git submodule update --init```
- ```cd  mbedtls && git submodule update --init```
- ```make```
