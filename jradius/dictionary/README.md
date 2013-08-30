jradius-dictionary
==================

The default JRadius dictionary is very old

The POM in this directory will build the Diamond Light Source version of the JRadius dictionary, 
which contains several added attributes (amongst those, the GSS-* and the SAML-AAA-Assertion attributes).

This POM expects you to copy the /usr/share/freeradius directory into the source tree 
(into the jradius/freeradius/ directory) and amend the POM to point to it. The next Maven build should 
automatically build a jradius-abfab-dictionary-[version].jar file that is 100% compatible with 
existing JRadius dictionaries. 

To use this dictionary, simply include the following dependency in the POM file that should consume it:

    <dependency>
       <groupId>uk.ac.diamond</groupId>
        <artifactId>jradius-abfab-dictionary</artifactId>
        <version>1.1.4</version>
    </dependency>

In your source code, continue to import it as follows:

import net.jradius.dictionary.[attribute class name];

Known Issues:
=============

The dictionary.alcatel.sr dictionary contains enumerations called 'null'. This conflicts with the 
reserved word 'null' in Java. Rename each enumeration to 'nul' before building. It does not impact
the use of the classes or a RADIUS conversation. This has been raised with Coova.
