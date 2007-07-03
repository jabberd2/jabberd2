<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="xml" indent="yes" />
	<xsl:template match="/">
		<Include Id="VersionInclude">
			<xsl:apply-templates />
		</Include>
	</xsl:template>
	<xsl:template match="entry">
		<xsl:text disable-output-escaping="yes">&#x9;&lt;?</xsl:text>define ProductRevision = "<xsl:value-of select="@revision"/>" <xsl:text disable-output-escaping="yes">?&gt;&#xA;</xsl:text>
		<xsl:text disable-output-escaping="yes">&#x9;&lt;?</xsl:text>define ProductVersion = "2.1svn<xsl:value-of select="@revision"/>" <xsl:text disable-output-escaping="yes">?&gt;&#xA;</xsl:text>
		<xsl:text disable-output-escaping="yes">&#x9;&lt;?</xsl:text>define ProductFileVersion = "1.0.<xsl:value-of select="@revision"/>" <xsl:text disable-output-escaping="yes">?&gt;&#xA;</xsl:text>
		<xsl:apply-templates select="url" />
	</xsl:template>
	<xsl:template match="url">
		<xsl:text disable-output-escaping="yes">&#x9;&lt;?</xsl:text>define ProductURL = "<xsl:value-of select="."/>" <xsl:text disable-output-escaping="yes">?&gt;</xsl:text>
	</xsl:template>
</xsl:stylesheet>