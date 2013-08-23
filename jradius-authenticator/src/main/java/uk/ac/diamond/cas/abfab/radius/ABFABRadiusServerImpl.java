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

// JRadius classes
import net.jradius.client.RadiusClient;
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

// These are standard between CAS v3.5.2 and v4.0.0
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.jasig.cas.adaptors.radius.RadiusServer;

// These are back-ported from CAS v4.0.0
import org.jasig.cas.adaptors.radius.RadiusProtocol;
import org.jasig.cas.adaptors.radius.RadiusClientFactory;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a RadiusServer that utilizes the JRadius packages available
 * at <a href="http://jradius.sf.net">http://jradius.sf.net</a>.
 *
 * @author Scott Battaglia
 * @author Marvin S. Addison
 * @author Stefan Paetow
 * @since 3.1
 */
public final class ABFABRadiusServerImpl implements RadiusServer {

    /** Default retry count, {@value}. */
    public static final int DEFAULT_RETRY_COUNT = 3;

    /** Logger instance. */
    private static final Logger LOGGER = LoggerFactory.getLogger(ABFABRadiusServerImpl.class);

    /** RADIUS protocol. */
    @NotNull
    private final RadiusProtocol protocol;

    /** Produces RADIUS client instances for authentication. */
    @NotNull
    private final RadiusClientFactory radiusClientFactory;

    /** Number of times to retry authentication when no response is received. */
    @Min(0)
    private int retries = DEFAULT_RETRY_COUNT;

    /** Load the dictionary implementation. */
    static {
        AttributeFactory
        .loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");
    }

    public ABFABRadiusServerImpl(final RadiusProtocol protocol, final RadiusClientFactory clientFactory) {
        this.protocol = protocol;
        this.radiusClientFactory = clientFactory;
    }

    @Override
    public boolean authenticate(
    		final UsernamePasswordCredentials usernamePasswordCredentials) {
    	return (this.authenticateEx(usernamePasswordCredentials) instanceof AccessAccept);
    }
    
    public RadiusPacket authenticateEx(final UsernamePasswordCredentials credentials) 
    		throws IllegalArgumentException, IllegalStateException {

        final AttributeList attributeList = new AttributeList();
        attributeList.add(new Attr_UserName(credentials
            .getUsername()));
        attributeList.add(new Attr_UserPassword(credentials
            .getPassword()));

        // give it the GSS Service Name and Host Name attributes
        attributeList.add(new Attr_GSSAcceptorServiceName("cas"));
        try {
        	attributeList.add(new Attr_GSSAcceptorHostName(InetAddress.getLocalHost().getCanonicalHostName()));
        } catch (final UnknownHostException e) {
        	attributeList.add(new Attr_GSSAcceptorHostName("localhost"));
        }

        final RadiusClient client = this.radiusClientFactory.newInstance();
        try {
            final AccessRequest request = new AccessRequest(client, attributeList);
            final RadiusPacket response = client.authenticate(
                    request,
                    RadiusClient.getAuthProtocol(this.protocol.getName()),
                    this.retries);

            LOGGER.debug("RADIUS response from {}: {}",
                    client.getRemoteInetAddress().getCanonicalHostName(),
                    response.getClass().getName());

            return response; 
        } catch (final UnknownAttributeException e) {
            throw new IllegalArgumentException(
                    "Passed an unknown attribute to RADIUS client: "
                        + e.getMessage());
        } catch (final RadiusException e) {
            throw new IllegalStateException(
                    "Received response that puts RadiusClient into illegal state: "
                        + e.getMessage());
        } finally {
            client.close();
        }
    }
}
