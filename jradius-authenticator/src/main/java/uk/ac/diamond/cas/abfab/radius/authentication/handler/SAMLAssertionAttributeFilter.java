package uk.ac.diamond.cas.abfab.radius.authentication.handler;

import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import net.jradius.packet.attribute.RadiusAttribute;
import net.jradius.packet.attribute.value.AttributeValue;
import net.jradius.packet.attribute.value.StringValue;

public class SAMLAssertionAttributeFilter {
	
	/** The SAML Assertion Attribute name in RADIUS */
	private final static String attributeName = "SAML-AAA-Assertion";
	
	/** The attributes used to initialise this class */
    private AttributeList attributes;

	/**
	 * @param attributes A JRadius AttributeList to filter
	 */
    public SAMLAssertionAttributeFilter(
			final AttributeList attributes) {
		this.attributes = attributes;
	}
    
	/**
	 * @return a string representing the complete attribute
	 */
    public String filter() throws UnknownAttributeException {
		StringBuilder sb = new StringBuilder();
		final Object[] attributeArray = attributes.getArray(AttributeFactory.getTypeByName(attributeName));
		for (final Object attributeObject : attributeArray) {
			if (attributeObject instanceof RadiusAttribute) {
				final AttributeValue av = ((RadiusAttribute) attributeObject).getValue();
				final String s = ((StringValue) av).toString(); 
				sb.append(s);
			}
		}
		return sb.toString();
    }
    
	/**
	 * @param Reset the internal attributes to the list passed in
	 */
	public void setAttributes(final AttributeList attributes) {
		this.attributes = attributes;
	}

	/**
	 * @return the attributes
	 */
	public AttributeList getAttributes() {
		return attributes;
	}
}
