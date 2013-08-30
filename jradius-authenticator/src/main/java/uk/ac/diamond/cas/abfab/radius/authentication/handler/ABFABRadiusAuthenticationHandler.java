/*
 * Diamond Light Source Limited licenses this file to you 
 * under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the 
 * License.  You may obtain a copy of the License at the 
 * following location:
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Portions of this file were licensed to Jasig under one or 
 * more contributor license agreements. See the NOTICE file 
 * distributed with this work for additional information 
 * regarding copyright ownership.
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package uk.ac.diamond.cas.abfab.radius.authentication.handler;

import java.util.List;

import javax.management.AttributeNotFoundException;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeList;

import org.jasig.cas.adaptors.radius.RadiusServer;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;

import uk.ac.diamond.cas.abfab.radius.ABFABRadiusServerImpl;

/**
 * ABFAB Authentication Handler to authenticate a user against a Moonshot (ABFAB) RADIUS server.
 * It consumes the returned SAML assertion on successful authentication, then updates 
 * the Credentials with the updated information
 * 
 * @author Stefan Paetow
 * @version $Revision$ $Date$
 * @since 3.5.2
 */
public class ABFABRadiusAuthenticationHandler extends
    AbstractUsernamePasswordAuthenticationHandler {

    /** Array of RADIUS servers to authenticate against. */
    @NotNull
    @Size(min=1)
    private List<RadiusServer> servers;

    /**
     * Determines whether to fail over to the next configured RadiusServer if
     * there was an exception.
     */
    private boolean failoverOnException;

    /**
     * Determines whether to fail over to the next configured RadiusServer if
     * there was an authentication failure.
     */
    private boolean failoverOnAuthenticationFailure;

    /**
     * Identifies the eventual principal in the SAML response in the ABFAB 
     * RADIUS packet. We feed that back into our SAML disassembler
     */
    private String principalIdentifierURN;

    /**
     * Authenticates the given credentials against the list of RADIUS servers,
     * and extends the service to retrieve the ultimate principal as returned in
     * a SAML assertion
     * @param credentials the username and password to authenticate
     * @return true (accept) or false (deny)
     * @throws AuthenticationException
     */
    protected final boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials) throws AuthenticationException {

        for (final RadiusServer radiusServer : this.servers) {
            try {
            	// let's initialise the variable to make Java happy
            	boolean response;
            	
            	if (!(radiusServer instanceof ABFABRadiusServerImpl)) {
                	response = radiusServer.authenticate(credentials);
            	} else {
                	RadiusPacket radiusResponse = ((ABFABRadiusServerImpl) radiusServer).authenticateEx(credentials);
                	response = (radiusResponse instanceof AccessAccept);
            		
	                // We had a successful authentication, and we have our extended server implementor
	                if (response) {
	
	                	// get the list of attributes, then feed it into the SAMLAssertionFilter
	            		final SAMLAssertionAttributeFilter samlAssertionFilter = 
	            				new SAMLAssertionAttributeFilter(radiusResponse.getAttributes());
	            		try {
	            			final String samlAssertion = samlAssertionFilter.getAssertion();
	                        log
	                        .debug("Successfully extracted SAML assertion from RADIUS response: {}", samlAssertion);
	                		
	                        // try to load the assertion into a document
	                        final SAMLAssertionAttributeExtractor samlExtractor = new SAMLAssertionAttributeExtractor(samlAssertion);
	                        if (!samlExtractor.isEmpty()) {
	                            log
	                            .debug("Successfully parsed SAML assertion into XML document");
	                        }
	                        
	                    	try {
	                    		if (samlExtractor.getAttributeStatement().hasChildren()) {
		                            log
		                            .debug("Found attribute statement in SAML2 assertion.");
	                    		}
	                            
	                            final String newCredential = samlExtractor.getAttributeValue(principalIdentifierURN);
	                            if (!newCredential.isEmpty()) {
	                    			log
	                    			.info("Authentication was successful. Credential {} mapped to {}", credentials.getUsername(), 
	                    					newCredential);
	                    			
	                    			// set the credential
	                            	credentials.setUsername(newCredential);
	                            	credentials.setPassword("");
	                            } else {
	                    			log
	                    			.info("Authentication was successful. Credential mapping for {} failed. Continuing with existing credentials", 
	                    					credentials.getUsername());
	                            }
	    	        		} catch (final UnmarshallingException e) {
	                			log
	                			.error("Authentication was successful, unable to load the SAML assertion for information retrieval!");
	                    	} catch (final IndexOutOfBoundsException e) {
	                            log
	                            .error("Authentication was successful, no attribute statement found in the SAML assertion!");
	    	        		} catch (final AttributeNotFoundException e) {
	                			log
	                			.error("Authentication was successful, unable to retrieve attribute {} from SAML assertion!", 
	                					principalIdentifierURN);
	                    	}
	                		
	            		} catch (final UnknownAttributeException e) {
	            			log
	            			.error("Authentication was successful, but SAML assertion was not present in RADIUS response!");
		        		} catch (final ConfigurationException e) {
	            			log
	            			.error("Authentication was successful, but SAML library initialisation failed!");
		        		} catch (final XMLParserException e) {
	            			log
	            			.error("Authentication was successful, but parsing the included SAML assertion failed!");
		        		} catch (final Exception e) {
		        			log
		        			.error("Authentication was successful, but another error occurred: " + e.toString());
		        		}
	            	}
            	}
                
                if (response
                    || (!response && !this.failoverOnAuthenticationFailure)) {
                    return response;
                }

                log
                    .debug("Failing over to next handler because failoverOnAuthenticationFailure is set to true.");
            } catch (Exception e) {
                if (!this.failoverOnException) {
                    log
                        .warn("Failover disabled.  Returning false for authentication request.");
                } else {
                    log.warn("Failover enabled.  Trying next RadiusServer.");
                }
            }
        }

        return false;
    }

	/**
     * Determines whether to fail over to the next configured RadiusServer if
     * there was an authentication failure.
     * 
     * @param failoverOnAuthenticationFailure boolean on whether to failover or
     * not.
     */
    public void setFailoverOnAuthenticationFailure(
        final boolean failoverOnAuthenticationFailure) {
        this.failoverOnAuthenticationFailure = failoverOnAuthenticationFailure;
    }

    /**
     * Determines whether to fail over to the next configured RadiusServer if
     * there was an exception.
     * 
     * @param failoverOnException boolean on whether to failover or not.
     */
    public void setFailoverOnException(final boolean failoverOnException) {
        this.failoverOnException = failoverOnException;
    }

    /**
     * Identifies the eventual principal in the SAML response in the ABFAB 
     * RADIUS packet. We feed that back into our SAML disassembler
     * 
     * @param principalIdentifierURN string identifying the eventual principal that we reset the credentials to.
     */
    public void setPrincipalIdentifierURN(final String principalIdentifierURN) {
        this.principalIdentifierURN = principalIdentifierURN;
    }

    public void setServers(final List<RadiusServer> servers) {
        this.servers = servers;
    }
}
