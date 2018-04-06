<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
xmlns:fo="http://www.w3.org/1999/XSL/Format" >
 <xsl:param name="filename"/>
 <xsl:output method="text" omit-xml-declaration="yes" indent="no"/>

 <xsl:template match="text()"/>

 <xsl:template match="model/object">
  <xsl:apply-templates select="parameter">
   <xsl:with-param name="ParentObjectName" select="@name"/>
  </xsl:apply-templates>
 </xsl:template>

 <xsl:template match="parameter">
  <xsl:param name="ParentObjectName"/>

  <xsl:text>m["</xsl:text>
  <xsl:value-of select="value/@hash"/>
  <xsl:text>"] = "</xsl:text>
  <xsl:value-of select="$filename" />
  <xsl:text>/</xsl:text>
  <xsl:value-of select="$ParentObjectName"/>
  <xsl:text>/</xsl:text>
  <xsl:value-of select="@name"/>
  <xsl:text>"; 
</xsl:text>
 </xsl:template>

</xsl:stylesheet>
