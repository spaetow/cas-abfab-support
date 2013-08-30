/*
 * Diamond Light Source Limited licenses this file to you 
 * under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the 
 * License.  You may obtain a copy of the License at the 
 * following location:
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
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
import java.security.GeneralSecurityException;

import javax.management.AttributeNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeList;

import org.jasig.cas.adaptors.radius.RadiusServer;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;

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
public class ABFABRadiusAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

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
    @Override
    protected final Principal authenticateUsernamePasswordInternal(final String username, final String password)
            throws GeneralSecurityException, PreventedException {

        for (final RadiusServer radiusServer : this.servers) {
            logger.debug("Attempting to authenticate {} at {}", username, radiusServer);
            try {
                if (radiusServer instanceof ABFABRadiusServerImpl) {
                    RadiusPacket radiusResponse = ((ABFABRadiusServerImpl) radiusServer).authenticateEx(username, password);
                    
                    // We had a successful authentication, and we have our extended server implementor
                    if (radiusResponse instanceof AccessAccept) {
    
                        // get the list of attributes, then feed it into the SAMLAssertionFilter
                        final SAMLAssertionAttributeFilter samlAssertionFilter = 
                                new SAMLAssertionAttributeFilter(radiusResponse.getAttributes());
                        try {
                            final String samlAssertion = samlAssertionFilter.getAssertion();
                            logger.debug("Successfully extracted SAML assertion from RADIUS response: {}", samlAssertion);
                            
                            // try to load the assertion into a document
                            final SAMLAssertionAttributeExtractor samlExtractor = new SAMLAssertionAttributeExtractor(samlAssertion);
                            if (!samlExtractor.isEmpty()) {
                                logger.debug("Successfully parsed SAML assertion into XML document");
                            }
                            try {
                                if (samlExtractor.getAttributeStatement().hasChildren()) {
                                    logger.debug("Found attribute statement in SAML2 assertion.");
                                }
                                
                                final String newCredential = samlExtractor.getAttributeValue(principalIdentifierURN);
                                if (!newCredential.isEmpty()) {
                                    logger.info("Authentication was successful. Credential {} mapped to {}", username, newCredential);
                                    // if we retrieved a credential from the assertion, return it here
                                    return new SimplePrincipal(newCredential);
                                } else {
                                    logger.info("Authentication was successful. Credential mapping for {} failed. Continuing with existing credentials", 
                                            username);
                                }
                            } catch (final UnmarshallingException e) {
                                logger.error("Authentication was successful, unable to load the SAML assertion for information retrieval!");
                            } catch (final IndexOutOfBoundsException e) {
                                logger.error("Authentication was successful, no attribute statement found in the SAML assertion!");
                            } catch (final AttributeNotFoundException e) {
                                logger.error("Authentication was successful, unable to retrieve attribute {} from SAML assertion!", 
                                        principalIdentifierURN);
                            }

                        } catch (final UnknownAttributeException e) {
                            logger.error("Authentication was successful, but SAML assertion was not present in RADIUS response!");
                        } catch (final ConfigurationException e) {
                            logger.error("Authentication was successful, but SAML library initialisation failed!");
                        } catch (final XMLParserException e) {
                            logger.error("Authentication was successful, but parsing the included SAML assertion failed!");
                        } catch (final Exception e) {
                            logger.error("Authentication was successful, but another error occurred: " + e.toString());
                        }

                        // by this time we still only have the username that was entered, so return a principal here
                        return new SimplePrincipal(username);

                    } else if (!this.failoverOnAuthenticationFailure) {
                        throw new FailedLoginException();
                    }
                    logger.debug("failoverOnAuthenticationFailure enabled -- trying next server");
                } else {
                    // do what the classic JRadiusServerImpl does
                    if (radiusServer.authenticate(username, password)) {
                        return new SimplePrincipal(username);
                    } else if (!this.failoverOnAuthenticationFailure) {
                        throw new FailedLoginException();
                    }
                    logger.debug("failoverOnAuthenticationFailure enabled -- trying next server");
                }
            } catch (final PreventedException e) {
                if (!this.failoverOnException) {
                    throw e;
                }
                logger.warn("failoverOnException enabled -- trying next server.", e);
            }
        }
        throw new FailedLoginException();
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
