# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112081");
  script_version("2025-03-21T15:40:43+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-10-13 13:12:41 +0200 (Fri, 13 Oct 2017)");
  script_name("HTTP Security Headers Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#div-headers");
  script_xref(name:"URL", value:"https://securityheaders.com/");

  script_tag(name:"summary", value:"All known security headers are being checked on the remote web
  server.

  On completion a report will hand back whether a specific security header has been implemented
  (including its value and if it is deprecated) or is missing on the target.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

# The 304 status code has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
# e.g. mod_headers from Apache won't add additional headers on this code so don't complain about a missing header.
# nb: There might be still some web servers sending the headers on a 304 status code so we're still reporting it below if there was a header included.
if( banner =~ "^HTTP/1\.[01] 304" )
  has_304 = TRUE;

headers_array = make_array();
missing_array = make_array();

known_headers = make_array( "X-Frame-Options", "https://owasp.org/www-project-secure-headers/#x-frame-options",
                            "X-XSS-Protection", "https://owasp.org/www-project-secure-headers/#x-xss-protection, Note: Most major browsers have dropped / deprecated support for this header in 2020.",
                            "X-Content-Type-Options", "https://owasp.org/www-project-secure-headers/#x-content-type-options",
                            "Content-Security-Policy", "https://owasp.org/www-project-secure-headers/#content-security-policy",
                            "X-Permitted-Cross-Domain-Policies", "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies",
                            "Referrer-Policy", "https://owasp.org/www-project-secure-headers/#referrer-policy",
                            "Feature-Policy", "https://owasp.org/www-project-secure-headers/#feature-policy, Note: The Feature Policy header has been renamed to Permissions Policy",
                            "Permissions-Policy", "https://w3c.github.io/webappsec-feature-policy/#permissions-policy-http-header-field",
                            "Document-Policy", "https://w3c.github.io/webappsec-feature-policy/document-policy#document-policy-http-header",
                            "Cross-Origin-Embedder-Policy", "https://scotthelme.co.uk/coop-and-coep/, Note: This is an upcoming header",
                            "Cross-Origin-Opener-Policy", "https://scotthelme.co.uk/coop-and-coep/, Note: This is an upcoming header",
                            "Cross-Origin-Resource-Policy", "https://scotthelme.co.uk/coop-and-coep/, Note: This is an upcoming header",
                            "Sec-Fetch-Site", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#fetch_metadata_request_headers, Note: This is a new header supported only in newer browsers like e.g. Firefox 90",
                            "Sec-Fetch-Mode", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#fetch_metadata_request_headers, Note: This is a new header supported only in newer browsers like e.g. Firefox 90",
                            "Sec-Fetch-User", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#fetch_metadata_request_headers, Note: This is a new header supported only in newer browsers like e.g. Firefox 90",
                            "Sec-Fetch-Dest", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#fetch_metadata_request_headers, Note: This is a new header supported only in newer browsers like e.g. Firefox 90" );

# nb: Those are only expected on HTTPS services
if( get_port_transport( port ) > ENCAPS_IP ) {
  known_headers["Strict-Transport-Security"] = "Please check the output of the VTs including 'SSL/TLS:' and 'HSTS' in their name for more information and configuration help.";
  known_headers["Public-Key-Pins"] = "Please check the output of the VTs including 'SSL/TLS:' and 'HPKP' in their name for more information and configuration help. Note: Most major browsers have dropped / deprecated support for this header in 2020.";
  known_headers["Expect-CT"] = "https://owasp.org/www-project-secure-headers/#expect-ct, Note: This is an upcoming header";
}

foreach known_header( keys( known_headers ) ) {
  headergrep = egrep( string:banner, pattern:"^" + known_header + "\s*:.+", icase:TRUE );

  if( headergrep ) {
    found_headers = TRUE;
    header_split = split( headergrep, sep:":", keep:FALSE );
    header_field = chomp( header_split[0] );

    # nb: As there might be e.g. https:// included in the value we need to handle this a little
    # bit differently...
    header_value = chomp( str_replace( string:headergrep, find:header_split[0], replace:"" ) );

    # Drop some additional superfluous data
    header_value = ereg_replace( string:header_value, pattern:"^:?\s+", replace:"" );

    # Content-Security-Policy might have something like this:
    #
    # *snip* default-src 'self'; script-src 'self' 'nonce-<redacted>='; *snip*
    #
    # or just:
    #
    # Content-Security-Policy: object-src 'self'; script-src 'self' 'nonce-<redacted>'
    #
    # Clean-up this from dynamic data so we don't report differences on the delta report
    if( header_field =~ "Content-Security-Policy" )
      header_value = ereg_replace( string:header_value, pattern:"('nonce-)([^']+)(';?)", replace:"\1***replaced***\3" );

    headers_array[header_field] = header_value;

    set_kb_item( name:tolower( known_header ) + "/available", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/available/port", value:port );
    set_kb_item( name:tolower( known_header ) + "/" + port + "/banner", value:header_value );

  } else {

    if( has_304 )
      continue;

    missing_headers = TRUE;
    missing_array[known_header] = known_headers[known_header];
    set_kb_item( name:tolower( known_header ) + "/missing", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/missing/port", value:port );
  }
}

if( found_headers )
  report += text_format_table( array:headers_array, sep:" | ", columnheader:make_list( "Header Name", "Header Value" ) );

if( missing_headers ) {
  if( found_headers )
    report += '\n\n';
  report += text_format_table( array:missing_array, sep:" | ", columnheader:make_list( "Missing Headers", "More Information" ) );
}

if( has_304 ) {
  if( found_headers )
    report += '\n\n';
  report += "Note: The remote web server is currently responding with a '304' (Not Modified) status code for which no additional security headers are expected.";
}

if( strlen( report ) > 0 )
  log_message( port:port, data:report );

exit( 0 );
