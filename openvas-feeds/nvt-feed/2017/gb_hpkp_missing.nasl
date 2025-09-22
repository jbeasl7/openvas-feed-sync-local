# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108247");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HTTP Public Key Pinning (HPKP) Missing");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_hpkp_http_detect.nasl");
  script_mandatory_keys("hpkp/missing/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");
  script_xref(name:"URL", value:"https://httpd.apache.org/docs/current/mod/mod_headers.html#header");
  script_xref(name:"URL", value:"https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header");

  script_tag(name:"summary", value:"The remote web server is not enforcing HTTP Public Key Pinning
  (HPKP).

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"solution", value:"Enable HPKP or add / configure the required directives
  correctly following the guides linked in the references.

  Note: Some web servers are not sending headers on specific status codes by default. Please review
  your web server or application configuration to always send these headers on every response
  independently from the status code.

  - Apache: Use 'Header always set' instead of 'Header set'.

  - nginx: Append the 'always' keyword to each 'add_header' directive.

  For different applications or web severs please refer to the related documentation for a similar
  configuration possibility.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hpkp/missing/port" ) )
  exit( 0 );

max_age_missing = get_kb_item( "hpkp/max_age/missing/" + port );
max_age_zero    = get_kb_item( "hpkp/max_age/zero/" + port );
pin_missing     = get_kb_item( "hpkp/pin/missing/" + port );
pkp_banner      = get_kb_item( "hpkp/" + port + "/banner" );

if( max_age_missing ) {
  report = "The remote web server is sending a HPKP header but is missing the required 'max-age=' directive.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else if( max_age_zero ) {
  report = "The remote web server is sending a HPKP header but is defining a 'max-age=0' directive which disables HPKP for this host.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else if( pin_missing ) {
  report = "The remote web server is sending a HPKP header but is missing a (supported) 'pin-' directive. Note: Currently only pin-sha256 is defined/supported.";
  report += '\n\nHPKP-Header:\n\n' + pkp_banner;
} else {
  banner = get_kb_item( "www/banner/" + port + "/" );

  # Clean-up banner from dynamic data so we don't report differences on the delta report
  pattern = '([Dd]ate\\s*:\\s*|[Ee]xpires=|[Ee]xpires\\s*:\\s*|PHPSESSID=|[Ll]ast-[Mm]odified\\s*:\\s*|[Cc]ontent-[Ll]ength\\s*:\\s*|[Ss]et-[Cc]ookie\\s*:\\s*|[Ee][Tt]ag\\s*:\\s*(W/"|")?|[Ss]ession[Ii]d=)([0-9a-zA-Z :,-;=_%]+)';
  if( eregmatch( pattern:pattern, string:banner ) )
    banner = ereg_replace( string:banner, pattern:pattern, replace:"\1***replaced***" );

  # Content-Security-Policy might have something like this:
  #
  # *snip* default-src 'self'; script-src 'self' 'nonce-<redacted>='; *snip*
  #
  # or just:
  #
  # Content-Security-Policy: object-src 'self'; script-src 'self' 'nonce-<redacted>'
  #
  # Clean-up the banner from this dynamic data as well
  if( banner =~ "Content-Security-Policy\s*:" )
    banner = ereg_replace( string:banner, pattern:"([Cc]ontent-[Ss]ecurity-[Pp]olicy\s*:.+'nonce-)([^']+)(';?)", replace:"\1***replaced***\3" );

  report = "The remote web server is not enforcing HPKP.";
  report += '\n\nHTTP-Banner:\n\n' + chomp( banner );
}

log_message( port:port, data:report );
exit( 0 );
