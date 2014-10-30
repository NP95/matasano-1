matasano
========

Code &amp; solutions for the matasano crypto challenge (http://cryptopals.com).

Be warned: this code is **VERY** hacky!

**Dependencies**:

- OpenSSL (I'm using v1.0.1j)

Code Structure:

    include/   - contains header files possibly used across multiple sets
    src/       - contains src files possibly used across multiple sets
    setX/      - contains files specific for the particular set
    Makefile   - Makefile used to build all or individual sets
    README.md  - this text

Progress:

    *** Set 1 ***
     Challenge  1 ..  8 [done]

    *** Set 2 ***
     Challenge  9 .. 16 [done]

    *** Set 3 ***
     Challenge 17 .. 24 [done]

    *** Set 4 ***
     Challenge 25 .. 32 [done]

    *** Set 5 ***
     Challenge 33 .. 40 [done]

    *** Set 6 ***
     Challenge 41       [done]
     Challenge 42    [working]

How to use:

    $ make
    $ cd setX; ./main.out

Now watch the show and have fun!
