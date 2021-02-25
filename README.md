We've reached the planned time of M3 of the DNSSEC key signing suite.  As
deliverable the GIT repository for the program source code and the repository
have been opened up and are visible at:

    https://github.com/NLnetLabs/dnssec-ceremony-doc/

    https://github.com/NLnetLabs/dnssec-ceremony-tools/tree/develop

As this is M3, this is still work-in-progress, as further integration with
OpenDNSSEC, testing and fine tuning are set for M4.  With M3 we have now
arrived where is is possible to "cook" recipies. 

# DNSSEC Key Signing Suite

## Off-line Key Signing (OKS) toolkit

The Key Signing Key (KSK) provides the proof that the operational keys
are validated by the owner, and as such the most sensitive part of the keyset.
Signing the keyset with the KSK in a separate off-line environment ensures
ownership of the domain cannot be stolen digitally and can be demonstrated by
signing the keyset in a (semi) public ceremony.

The rationale, procedure and information exchange are further described in
the documentation repository:

    https://github.com/NLnetLabs/dnssec-ceremony-doc/

### Design principles

The goal is to have the important key material stored in a off-line environment
only.  This environment is further on called the bunker.  In this bunker
the data needed in the operational environment is signed.  Enough signed
material should be produced such that the operational environment can continue
for some time.  For DNSSEC this involves creating multiple signed key set,
accommodating for key rolls, generating and disposing keys and either importing
or exporting key material.

In the bunker all steps should be transparent, simple, without failure or
exceptions.  No choices in the signing process should be needed and everything
should be as simple as possible.

All complications should be done beforehand and only a fixed 'recipe' should
be executed with simple steps of which the automation is clear and transparent.
A small clean set of software dependencies should be used because system
upgrades will be difficult.

The off-line key signing application execution is therefore three process
steps:

- The generation of a recipe, based on the current known state and used keys
  as known from the system with which to integrate.  Predict how many signed
  keysets must be made, defining the preconditions and other initial steps,
  etcetera.  The output is a recipe that comprises simple, self contained
  steps to be executed one after another.
  This generation is done beforehand and can be corrected if needed, as no
  actual change happens.  The recipe carried into the bunker can be verified
  beforehand and even tested in a separate environment if wanted.
- The cooking of the recipe in the bunker.  This reads and interprets the
  recipe steps one by one, performs the action and fills in the result in
  the recipe.  Apart from the sequence, steps are independent from each other
  and thus the flow and state can be kept simple.
- The augmented recipe with the results can then be carried from the bunker
  into the operational environment where its result can be used for the
  day to day activities.  Here the right signed keyset need to be picked from
  the cooked recipe, any new keys decoded and inserted into the local HSM,
  and so on.

A deliberate choice has been made to base the software on Python, to avoid
any complexity of program compilation and make the execution even more
transparent.  To further simplify, the software is contained within one
single Python source file and accompanied by a single configuration file
that contains environment specific parameters (and could therefore stay within
the bunker).  The input AND output is a single recipe file in JSON
format that gets deliberately overwritten as it is augmented and otherwise kept
as is.

### Prerequisites for the software: 

The following software requirements are needed on your system:

- Python 3.7 or better
- The python packages (installed using pip3 install):
  - hjson (alternative using json-tricks, or json is possible)
  - pyyaml
  - python-pkcs11 (/not/ pkcs11)
#
## Further steps

Completion of the minimal viable product will still include:

- Further explain/document configuration file
- Further explain default generated recipe file in depth, including
  symmetric key mechanism to exchange files between bunker and operational
  environment;
- Support for multiple repositories within the same recipe;
- Integration with OpenDNSSEC, mostly based on integration with the signer;
- More verbose output to the user regarding the processing of each step
- further completion of the produce and consumation of the recipes, including
  multiple ZSK rolls.

### Foreseen limitations

- DNSSEC Algorithm support will remain at RSASHA based, not including MD5,
  nor eliptic curve (though these will not be difficult to add).
- Only a single KSK key roll within a single run will be planned, with the
  earliest convenient schedule.
- Only double DS based KSK rolls are planned, algorithm roll will not be
  tested.
- No additional provisioning will be planned for simultaneous KSK and ZSK
  rolls.
- produced recipes will be per domain/zone.
- the script only provides integration with OpenDNSSEC and contains no
  explicit extension points.

### Example test run.

This program was based on a sample run with SoftHSM, even though any compliant
PKCS#11 based solution will work.  The steps to install a working SoftHSM into
a separate ROOT directory are:

    mkdir ROOT
    cd ROOT
    ROOT=`pwd`
    cd ..
    wget 'https://dist.opendnssec.org/source/softhsm-2.5.0.tar.gz'
    ./configure --prefix=$ROOT --sbindir=$ROOT/bin --bindir=$ROOT/bin \
            --libexecdir=$ROOT/lib --sysconfdir=$ROOT/etc \
            --datarootdir=$ROOT \
            --disable-gost --disable-fips --disable-non-paged-memory \
            --disable-p11-kit --without-migrate 
    cd ..
    export PATH=$ROOT/bin:$PATH

Also create two tokens, one that acts as the HSM in the Bunker, and one for
the operational environment

    softhsm2-util --init-token --pin=1234 --so-pin=4321 --label Bunker --free
    softhsm2-util --init-token --pin=1234 --so-pin=4321 --label OKS  --free

There is an example recipe.json included in the source,  Within the bunker
this recipe can be processed using the command:

    oks cook

Input recipe and produced recipe are present in the source tree as
recipe.json and recipe.result (the latter would have overwritten the input
file).

Default filenames and locations for the recipe input/output file,
configuration file can be overriden using flags that are made clear when
invoking oks using the --help flag, or when invoked without arguments.

Even though integration with OpenDNSSEC is not completed, the tool can already
generate recipes for new or existing zones, the latter based on signed input
zones.

A recipe is produced using:

    oks produce nl. 2020-08-01 "First run"

This generates a recipe for the new zone "nl", generating instructions in the
recipe to create signed keysets until the 1st of august 2020.  The "First run"
description will be included in the recipe.

If you have an existing signed zone nl in zonefile "nl.zone" then the
generation will take this into account and use those keys and expiration
times.  You instruct the tool to use this input file using:

    oks -i nl.zone produce 2020-08-01 "Second run"

The rolling mechanism is however limited and partially controlled from the
key-and-signing-policy parameters in the configuration file.

### Example run with OpenDNSSEC

For a fully working example run with sample configuration and input files
including a OpenDNSSEC and SoftHSM setup see the example directory.
