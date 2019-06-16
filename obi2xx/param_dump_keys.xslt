<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
xmlns:fo="http://www.w3.org/1999/XSL/Format" >
 <xsl:output method="text" omit-xml-declaration="yes" indent="no"/>

 <xsl:template match="text()"/>

 <xsl:template match="ParameterList/O">
  <xsl:apply-templates select="P/N">
   <xsl:with-param name="ParentObjectName" select="N"/>
  </xsl:apply-templates>
 </xsl:template>

 <xsl:template match="P/N">
  <xsl:param name="ParentObjectName"/>

  <xsl:text>addHash(m, "</xsl:text>
  <xsl:value-of select="$ParentObjectName"/>
  <xsl:value-of select="text()"/>
  <xsl:text>");
</xsl:text>
 </xsl:template>

</xsl:stylesheet>
