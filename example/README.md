Let's get SoftHSM and OpenDNSSEC and install them in a location:

    mkdir ROOT
    wget -q https://dist.opendnssec.org/source/softhsm-2.6.1.tar.gz
    tar xzf softhsm-2.6.1.tar.gz
    cd softhsm-2.6.1
    ./configure --prefix=`pwd`/../ROOT --sbindir=`pwd`/../ROOT/bin \
      --disable-gost --without-p11-kit
    make all install
    cd ..
    wget -q https://dist.opendnssec.org/source/opendnssec-2.1.7.tar.gz
    tar xzf opendnssec-2.1.7.tar.gz
    cd opendnssec-2.1.7
    ./configure --prefix=`pwd`/../ROOT --sbindir=`pwd`/../ROOT/bin
    make all install
    cd ..
    export PATH=`pwd`/ROOT/bin:$PATH
    export SOFTHSM2_CONF=`pwd`/etc/softhsm2.conf

This example directory contains three configuration files, kasp.xml, conf.xml
and zonelist.xml which should be placed in the ROOT/etc/opendnssec
directory.  Also a softhsm2.conf that should be placed in ROOT/etc.
Edit them to replace "..." with the current directory where the directory ROOT
exists.  Also provided is a zone file for the example.com zone that we'll use.
copy the example.com to ROOT/var/lib/opendnssec/unsigned
Now we can initialize this setup:

    softhsm2-util --init-token --label=Bunker --pin=1234 --so-pin=1234 --free
    softhsm2-util --init-token --label=OKS    --pin=1234 --so-pin=1234 --free
    ods-enforcer-db-setup -f
    ods-control start
    ods-enforcer policy import
    ods-enforcer zone add -z example.com -p example
    ods-enforcer time leap
    ods-enforcer time leap
    ods-enforcer key ds-seen --all
    ods-enforcer stop

When copy-pasting these commands, do them individually to make sure every
command is completed.  The "time leap" command is not supported, and
illegally advances the zone time steps,  It will work within a test set up.
We now have a fully signed zone, and stopped the enforcer so wel can use
the signing ceremony.

We can produce a recipe for the coming year (assuming it is now still 2020).
For producing a recipe based on the corrent keys in use copy the signing
configation file (signconf) and the current state file of OpenDNSSEC 2.1
to the current working directory to be used as input:

    cp ROOT/var/opendnssec/signconf/example.com.xml   example.com.xml
    cp ROOT/var/opendnssec/signer/example.com.backup2 example.com

Also take the oks-working.conf and oks-bunker.conf configuration files from
this example directory and adapt any paths therein.

To create a recipe in the simulated operational environment:

    oks.py -c oks-working.conf produce example.com 2021-05-01 "Testing"

This will produce a recipe.json output file that can be used next.
To cook a recipe in the bunker environment:

    oks.py -c oks-bunker.conf -d -v cook

This will overwrite the recipe.json file and add the result to the file.
Which can now be used:

    oks.py -c oks-working.conf -d -v consume
    oks.py -c oks-working.conf -d -v consume now
    cp example.com.xml ROOT/var/opendnssec/signconf/example.com.xml
    ods-signer update example.com

For the coming period the last two commands can be used in a crontab on
an regular (e.g. hourly) basis to produce a new signconf file.

If you want to clean up and try again without reinstalling OpenDNSSEC and
SoftHSM, then try the following:

    ods-control stop
    rm -f var/opendnssec/signer/* var/opendnssec/enforcer/zones.xml
    echo '<?xml version="1.0" encoding="UTF-8"?><ZoneList></ZoneList>' \
      > etc/opendnssec/zonelist.xml
    for s in `softhsm2-util --show-slots | \
          sed -e 's/^ *Serial number: *\([0-9a-fA-f][0-9a-fA-F]*\)/\1/p' -e d`
    do
      softhsm2-util --delete-token --serial=$s
    done

And then continue from the first softhsm2-util command in the above example.
