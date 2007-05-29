<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text" indent="no"/>
<xsl:template match="entry">
#define SVN_REVISION    <xsl:value-of select="@revision"/>
#define SVN_VERSION     "2.1svn<xsl:value-of select="@revision"/>"
#define SVN_FILEVERSION 2,1,0,<xsl:value-of select="@revision"/>
<xsl:apply-templates select="url"/></xsl:template>
<xsl:template match="url">
#define SVN_URL         "<xsl:value-of select="."/>"
</xsl:template>
</xsl:stylesheet>