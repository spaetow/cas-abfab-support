package uk.ac.diamond.cas.abfab.radius.authentication.handler;

import java.io.StringReader;
import java.util.List;

import javax.management.AttributeNotFoundException;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


public class SAMLAssertionAttributeExtractor {
    
    /** Instance of logging for subclasses. */
    protected Logger log = LoggerFactory.getLogger(this.getClass());
    
    /** The assertion that you intend to extract an attribute from */
    private Document assertion;

    /**
     * @param assertion A SAML assertion in XML string form
     * @throws ConfigurationException, XMLParserException
     */
    public SAMLAssertionAttributeExtractor(
            final String assertion) throws ConfigurationException, XMLParserException {
        // Initialise the library
        DefaultBootstrap.bootstrap(); 
         
        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        
        // parse the XML document, and also set whether the assertion is empty or not
        this.assertion = ppMgr.parse(new StringReader(assertion));
    }
    
    /**
     * @return the XML document representing the SAML assertion
     */
    public Document getDocument() {
        return this.assertion;
    }
    
    /**
     * @return whether the SAML assertion is empty or not
     */
    public boolean isEmpty() {
        return this.assertion.hasChildNodes();
    }
    
    /**
     * @return the root element of the XML document
     * @throws UnmarshallingException 
     */
    public XMLObject unmarshall() throws UnmarshallingException {
        Element rootElement = this.assertion.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElement);
        
        return unmarshaller.unmarshall(rootElement);
    }
    
    /**
     * @param attributeId representing the attribute whose value you want to return
     * @return a string representing the attribute's value, returns null if attribute not found
     * @throws AttributeNotFoundException
     */
    public String getAttributeValue(final String attributeId) throws AttributeNotFoundException {
        try {
            AttributeStatement attributeStatement = this.getAttributeStatement(); 
            List<Attribute> attributes = attributeStatement.getAttributes();
            if (!attributes.isEmpty()) {
                for (Attribute attribute : attributes) {
                    if (attribute.getName().indexOf(attributeId) == 0) {
                        XMLObject attributeValue = attribute.getAttributeValues().get(0);
                        if (attributeValue instanceof XSString) {
                            return ((XSString) attributeValue).getValue();
                        } else if (attributeValue instanceof XSAny) {
                            return ((XSAny) attributeValue).getTextContent();
                        }
                    }
                }
            }
            throw new AttributeNotFoundException(
                    String.format("Attribute %s not found in SAML AttributeStatement", attributeId));
        } catch (final UnmarshallingException e) {
            throw new AttributeNotFoundException(
                    String.format("Unable to get attribute %s. Failed to load SAML assertion. Underlying error %s", 
                            attributeId, e.getMessage()));
        } catch (final IndexOutOfBoundsException e) {
            throw new AttributeNotFoundException(
                    String.format("Unable to get attribute %s. No AttributeStatement found in the SAML assertion.",attributeId));
        }
    }

    /**
     * @return an AttributeStatement from the SAML assertion
     * @throws UnmarshallingException, IndexOutOfBoundsException 
     */
    public AttributeStatement getAttributeStatement() throws UnmarshallingException, IndexOutOfBoundsException {
        /** 
         * SAML 2.0 schema definition makes room for 0 or more AttributeStatements, 
         * but currently must contain no more than one
         * 
         * http://blog.sweetxml.org/2007/08/who-needs-saml-v20-attribute-profiles.html
         */
        Assertion assertion = (Assertion) this.unmarshall();
        return assertion.getAttributeStatements().get(0);
    }
}
