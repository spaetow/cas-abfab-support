cas-abfab-support
=================

CAS support for ABFAB (Moonshot) authentication

This repository contains extensions of the cas-server-support-radius module which are CAS 3.5 and CAS 4.0 compatible.

It contains:

    ABFABRadiusAuthenticationHandler - An extension of the standard RadiusAuthenticationHandler
      - It deals with the SAML assertion returned in an Access-Accept packet from a Moonshot RADIUS 
        server.
      - New property "principalIdentifierURN" identifies which SAML attribute to use as credential
        
    ABFABRadiusServerImpl - An extension of the standard JRadiusServerImpl
      - Additional method "authenticateEx" performs standard authentication and returns the 
        Access-Accept packet received from the RADIUS server (used by ABFABRadiusAuthenticationHandler)
      - Adds GSS-* ABFAB (see http://datatracker.ietf.org/doc/draft-ietf-abfab-gss-eap/) attributes 
        to RADIUS request
      - In CAS 3.5.x specifically, enables EAP-TTLS authentication with inner protocols PAP, MD5 
        or EAP-MSCHAPv2

Prerequisites
-------------

The ABFAB components require the use of the Coova JRadius library, which in turn requires the IPDR base. To enable the use of these components, you must:

Define the Coova repository in the POM.XML file for the app using the ABFAB components:

      <repositories>
        <repository>
          <id>coova</id>
          <name>Coova Repository</name>
          <url>http://coova-dev.s3.amazonaws.com/mvn</url>
        </repository>
      </repositories>

You must install IPDR base manually using the below steps:
   - Download [org.ipdrjava_2.0.0.zip](http://sourceforge.net/projects/ipdr/files/java_ipdrbase/2.0.0/org.ipdrjava_2.0.0.zip/download)
   - Extract **org.ipdr_2.0.0/ipdr.jar**
   - Install it with Maven: *mvn install:install-file -DgroupId=ipdr -DartifactId=ipdrbase -Dversion=2.0.0 -Dpackaging=jar -Dfile=/path/to/extracted/ipdr.jar*

All other components should be available from Maven Central.

Usage
-----

Usage of ABFABRadiusServerImpl in the deployerConfigContext.xml matches the CAS 4.0.0 style, and is compatible with 
CAS 3.5.2:
    
    1. Include the following namespace:
    
    xmlns:c="http://www.springframework.org/schema/c"
    
    2. Specify your RadiusServer and radiusClientFactory beans (in CAS 3.x, no more constructor-arg 
       hell):
    
    <!-- RADIUS server protocol choice -->
    <bean id="RadiusServer_id1"
          class="uk.ac.diamond.cas.abfab.radius.ABFABRadiusServerImpl"
          c:protocol="EAP_TTLS_EAP_MSCHAPv2"
          c:clientFactory-ref="radiusClientFactory1" />
    
	<!-- RADIUS client factory 1 -->
    <bean id="radiusClientFactory1"
          class="org.jasig.cas.adaptors.radius.RadiusClientFactory"
          p:inetAddress="ip.address.here"
          p:sharedSecret="radius.shared.secret.here" />
          
    By specifying multiple RadiusServer beans with different protocol settings, you can try different 
    protocols for authentication. You can specify multiple radiusClientFactory beans, each with 
    different host names and shared secrets, and refer different RadiusServer beans to different 
    client factories. 
     
    3. In the "servers" property of (ABFAB)RadiusAuthenticationHandler, simply refer to the server(s) as 
    follows:
    
    <ref local="RadiusServer_id1" />
    :
    :

	4. Include Maven dependencies as follows:
	
	CAS 3.5.x:  
	
    <dependency>
      <groupId>uk.ac.diamond</groupId>
      <artifactId>diamond-cas3-abfab-support</artifactId>
      <version>0.1.0</version>
    </dependency>

	CAS 4.0.0:  
	
    <dependency>
      <groupId>uk.ac.diamond</groupId>
      <artifactId>diamond-cas4-abfab-support</artifactId>
      <version>0.1.0</version>
    </dependency>
	
This is still a work in progress.
