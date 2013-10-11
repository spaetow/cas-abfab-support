package uk.ac.diamond.cas.abfab.radius.authentication.handler;

import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import net.jradius.packet.attribute.RadiusAttribute;
import net.jradius.packet.attribute.value.StringValue;

public class SAMLAssertionAttributeFilter extends RADIUSAttributeFilter {
    
    /** The SAML Assertion Attribute name in RADIUS */
    private final static String attributeName = "SAML-AAA-Assertion";
    
    /**
     * @param attributes A JRadius AttributeList to filter
     */
    public SAMLAssertionAttributeFilter(
            final AttributeList attributes) {
       super(attributes);
    }
    
    /**
     * @return A string representing the complete attribute concatenated from all SAML-AAA-Assertion attributes
     */
    public String getAssertion() throws UnknownAttributeException {
        StringBuilder sb = new StringBuilder();
        final Object[] attributeArray = this.getAttribute(attributeName);
        for (final Object attributeObject : attributeArray) {
            if (attributeObject instanceof RadiusAttribute) {
                final StringValue sv = (StringValue) ((RadiusAttribute) attributeObject).getValue();
                sb.append(sv.toString());
            }
        }
        return sb.toString();
    }
}
