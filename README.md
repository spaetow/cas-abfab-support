cas-abfab-support
=================

CAS support for ABFAB (Moonshot) authentication

This module contains an extension of the cas-server-support-radius module (and currently is only CAS 3.5.x compatible).

It contains:

    ABFABRadiusAuthenticationHandler - An extension of the standard RadiusAuthenticationHandler
      - It deals with the SAML assertion returned in an Access-Accept packet from a Moonshot RADIUS server.
      - New property "principalIdentifierURN" identifies which SAML attribute to use as credential
        
    ABFABRadiusServerImpl - An extension of the standard JRadiusServerImpl
      - It deals with the increased complexity of the JRadius EAPTTLSAuthenticator
      - Additional method "authenticateEx" performs standard authentication and returns the Access-Accept packet
        received from the RADIUS server
      - New constructor parameter (constructor-arg 7) specifies the inner EAP authentication method. Default is PAP.
      
This is still a work in progress.
