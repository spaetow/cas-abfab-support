package uk.ac.diamond.cas.adaptors.radius;

import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import net.jradius.packet.attribute.RadiusAttribute;
import net.jradius.packet.attribute.value.StringValue;

public class RADIUSAttributeFilter {
    
    /** The attributes used to initialise this class */
    private AttributeList attributes;

    /**
     * @param attributes A JRadius AttributeList to filter
     */
    public RADIUSAttributeFilter(
            final AttributeList attributes) {
        this.attributes = attributes;
    }
    
    /**
     * @param attributeName A string representing the name of the attribute
     * @return Object array representing the attribute
     */
    public Object[] getAttribute(final String attributeName) throws UnknownAttributeException {
        final Object[] attributeArray = this.attributes.getArray(AttributeFactory.getTypeByName(attributeName));
        return attributeArray;
    }
    
    /**
     * @return The RADIUS attributes stored in this class
     */
    public AttributeList getAttributes() {
        return attributes;
    }
}
