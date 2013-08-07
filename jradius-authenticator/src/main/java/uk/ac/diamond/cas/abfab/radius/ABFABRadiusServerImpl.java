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

package uk.ac.diamond.cas.abfab.radius;

import java.net.InetAddress;
import java.net.UnknownHostException;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.PAPAuthenticator;
import net.jradius.client.auth.RadiusAuthenticator;
import net.jradius.client.auth.EAPTTLSAuthenticator;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.dictionary.Attr_GSSAcceptorHostName;
import net.jradius.dictionary.Attr_GSSAcceptorRealmName;
import net.jradius.dictionary.Attr_GSSAcceptorServiceName;
import net.jradius.dictionary.Attr_GSSAcceptorServiceSpecifics;
import net.jradius.exception.RadiusException;
import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.adaptors.radius.RadiusServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a RadiusServer based on the JRadiusServerImpl class
 * that utilizes the JRadius packages available at 
 * <a href="http://jradius.sf.net">http://jradius.sf.net</a>.
 * 
 * @author Scott Battaglia, extended by Stefan Paetow
 * @version $Revision$ $Date$
 * @since 3.1
 */
public final class ABFABRadiusServerImpl implements RadiusServer {

    private static final Logger LOG = LoggerFactory.getLogger(ABFABRadiusServerImpl.class);

    /** Default PAP Authenticator if no other one is specified. */
    private static final RadiusAuthenticator DEFAULT_RADIUS_AUTHENTICATOR = new PAPAuthenticator();

    /** Default port to do authentication on. */
    private static final int DEFAULT_AUTHENTICATION_PORT = 1812;

    /** Default port to do accounting on. */
    private static final int DEFAULT_ACCOUNTING_PORT = 1813;

    /** Default socket timeout time. */
    private static final int DEFAULT_SOCKET_TIMEOUT = 5;

    /** Default number of retries. */
    private static final int DEFAULT_NUMBER_OF_RETRIES = 3;

    /** Default inner protocol for EAP authenticators. */
	private static final String DEFAULT_EAP_INNER_PROTOCOL = "pap";

    /** The port to do accounting on. */
    private final int accountingPort;

    /** The port to do authentication on. */
    private final int authenticationPort;

    /** The timeout for sockets. */
    private final int socketTimeout;

    /** The conversion from hostname to an InetAddress. */
    private final InetAddress inetAddress;

    /** The shared secret to send to the RADIUS server. */
    private final String sharedSecret;

    /** The number of retries to do per authentication request. */
    private final int retries;

    /** The inner protocol for EAP. */
	private final String eapInnerProtocol;

    /** The local host's IP address. */
    private final InetAddress inetLocalHost;

    /** The RADIUS Authenticator to use. */
    private final RadiusAuthenticator radiusAuthenticator;
    
    /** Load the dictionary implementation. */
    static {
        AttributeFactory
            .loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");
    }

    /**
     * Simplest constructor to set the hostname and the shared secret. Uses
     * default values for everything else.
     * 
     * @param hostName the host name of the RADIUS server.
     * @param sharedSecret the shared secret with that server.
     * @throws UnknownHostException if the hostname cannot be resolved.
     */
    public ABFABRadiusServerImpl(final String hostName, final String sharedSecret)
        throws UnknownHostException {
        this(hostName, sharedSecret, DEFAULT_RADIUS_AUTHENTICATOR,
            DEFAULT_AUTHENTICATION_PORT);
    }

    /**
     * Constructor to set the host name, shared secret and authentication type.
     * 
     * @param hostName the host name of the RADIUS server.
     * @param sharedSecret the shared secret with that server.
     * @param radiusAuthenticator the RADIUS authenticator to use.
     * @throws UnknownHostException if the hostname cannot be resolved.
     */
    public ABFABRadiusServerImpl(final String hostName, final String sharedSecret,
        final RadiusAuthenticator radiusAuthenticator)
        throws UnknownHostException {
        this(hostName, sharedSecret, radiusAuthenticator,
            DEFAULT_AUTHENTICATION_PORT);
    }

    /**
     * Constructor that accepts the host name, shared secret, authentication type,
     * and port.
     * 
     * @param hostName the host name of the RADIUS server.
     * @param sharedSecret the shared secret with that server.
     * @param radiusAuthenticator the RADIUS authenticator to use.
     * @param authenticationPort the port to use to authenticate on.
     * @throws UnknownHostException if the hostname cannot be resolved.
     */
    public ABFABRadiusServerImpl(final String hostName, final String sharedSecret,
        final RadiusAuthenticator radiusAuthenticator,
        final int authenticationPort) throws UnknownHostException {
        this(hostName, sharedSecret, radiusAuthenticator, authenticationPort,
            DEFAULT_ACCOUNTING_PORT);
    }

    /**
     * Constructor that accepts the host name, shared secret, authentication type,
     * authentication port, and accounting port.
     * 
     * @param hostName the host name of the RADIUS server.
     * @param sharedSecret the shared secret with that server.
     * @param radiusAuthenticator the RADIUS authenticator to use.
     * @param authenticationPort the port to use to authenticate on.
     * @param accountingPort the port to use to do accounting.
     * @throws UnknownHostException if the hostname cannot be resolved.
     */
    public ABFABRadiusServerImpl(final String hostName, final String sharedSecret,
        final RadiusAuthenticator radiusAuthenticator,
        final int authenticationPort, final int accountingPort)
        throws UnknownHostException {
        this(hostName, sharedSecret, radiusAuthenticator, authenticationPort,
            accountingPort, DEFAULT_SOCKET_TIMEOUT, DEFAULT_NUMBER_OF_RETRIES,
            DEFAULT_EAP_INNER_PROTOCOL);
    }

    /**
     * Constructor that accepts the host name, shared secret, authentication type,
     * authentication port, accounting port, timeout and number of retries.
     * @param hostName the host name of the RADIUS server.
     * @param sharedSecret the shared secret with that server.
     * @param radiusAuthenticator the RADIUS authenticator to use.
     * @param authenticationPort the port to use to authenticate on.
     * @param accountingPort the port to use to do accounting.
     * @param socketTimeout the time before the RADIUS request times out.
     * @param retries the number of retries for authentication.
     * @param innerProtocol the inner tunnel protocol for EAP-TTLS.
     * @throws UnknownHostException if the hostname cannot be resolved.
     */
    public ABFABRadiusServerImpl(final String hostName, final String sharedSecret,
        final RadiusAuthenticator radiusAuthenticator,
        final int authenticationPort, final int accountingPort,
        final int socketTimeout, final int retries, final String innerProtocol) throws UnknownHostException {
        this.sharedSecret = sharedSecret;
        this.authenticationPort = authenticationPort;
        this.accountingPort = accountingPort;
        this.socketTimeout = socketTimeout;
        this.retries = retries;
        this.radiusAuthenticator = radiusAuthenticator;
        this.eapInnerProtocol = innerProtocol;
        this.inetAddress = InetAddress.getByName(hostName);
        this.inetLocalHost = InetAddress.getLocalHost();
    }

    public boolean authenticate(
    		final UsernamePasswordCredentials usernamePasswordCredentials) {
    	return (this.authenticateEx(usernamePasswordCredentials) instanceof AccessAccept);
    }
    
    public RadiusPacket authenticateEx(
        final UsernamePasswordCredentials usernamePasswordCredentials) {
        final RadiusClient radiusClient = getNewRadiusClient();

        final AttributeList attributeList = new AttributeList();
        attributeList.add(new Attr_UserName(usernamePasswordCredentials
            .getUsername()));
        attributeList.add(new Attr_UserPassword(usernamePasswordCredentials
            .getPassword()));
        
        // give it the GSS Service Name and Host Name attributes
        attributeList.add(new Attr_GSSAcceptorServiceName("cas"));
        attributeList.add(new Attr_GSSAcceptorHostName(inetLocalHost.getCanonicalHostName()));
        
        final AccessRequest request = new AccessRequest(radiusClient,
            attributeList);

        try {
        	RadiusAuthenticator radiusAuthenticator = getNewRadiusAuthenticator();
        	if (this.radiusAuthenticator instanceof EAPTTLSAuthenticator) {
        		((EAPTTLSAuthenticator) radiusAuthenticator).setInnerProtocol(this.eapInnerProtocol);
        	}
        	final RadiusPacket response = radiusClient.authenticate(request, radiusAuthenticator, this.retries);
            
            // accepted
            if (response instanceof AccessAccept) {
                LOG.debug("Authentication request suceeded for host: {} and username {}", 
                    this.inetAddress.getCanonicalHostName(), usernamePasswordCredentials.getUsername());
            } else {
	            // rejected
	            LOG.debug("Authentication request failed for host: {} and username {}",
	                this.inetAddress.getCanonicalHostName(), usernamePasswordCredentials.getUsername());
            }
            return response;
        } catch (final UnknownAttributeException e) {
            throw new IllegalArgumentException(
                "Passed an unknown attribute to RADIUS client: "
                    + e.getMessage());
        } catch (final RadiusException e) {
            throw new IllegalStateException(
                "Received response that puts RadiusClient into illegal state: "
                    + e.getMessage());
        }
    }

    private RadiusClient getNewRadiusClient() {
        return new RadiusClient(this.inetAddress, this.sharedSecret,
            this.authenticationPort, this.accountingPort, this.socketTimeout);
    }

    /**
     * Function that returns a new instance of an authenticator.
     * @return radiusAuthenticator The new authentication instance.
     */
    private RadiusAuthenticator getNewRadiusAuthenticator() {
        RadiusAuthenticator radiusAuthenticator = null;
        Class <?> c = this.radiusAuthenticator.getClass();
        try {
            radiusAuthenticator = (RadiusAuthenticator) c.newInstance();
        } catch (final Exception e) {
            LOG.error("Unable to create new instance of authenticator", e);
            radiusAuthenticator = this.radiusAuthenticator;
        }
        return radiusAuthenticator;
    }
}
