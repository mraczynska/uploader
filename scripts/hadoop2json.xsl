<?xml version="1.0" encoding="UTF-8" ?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" encoding="utf-8"/>

<xsl:template match="/">
  <xsl:text>{</xsl:text>
    <xsl:for-each select="configuration/property">
      <xsl:text>"</xsl:text><xsl:value-of select="name"/>":"<xsl:value-of select="value"/><xsl:text>"</xsl:text>
      <xsl:if test="count(following-sibling::*) &gt; 0">,</xsl:if>
    </xsl:for-each>
  <xsl:text>}</xsl:text>
</xsl:template>

</xsl:stylesheet>
