# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113045");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-11-07 10:06:44 +0100 (Tue, 07 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SSL/TLS: Expect Certificate Transparency (Expect-CT) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SSL and TLS");
  # nb: Don't add a dependency to e.g. webmirror.nasl or DDI_Directory_Scanner.nasl
  # to allow a minimal SSL/TLS check configuration.
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_ssl_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"Checks if the remote web server has Expect-CT enabled.");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#expect-ct");
  script_xref(name:"URL", value:"https://scotthelme.co.uk/a-new-security-header-expect-ct/");
  script_xref(name:"URL", value:"http://httpwg.org/http-extensions/expect-ct.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default: 443, ignore_cgi_disabled: TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 )
  exit( 0 );

banner = http_get_remote_headers( port: port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

if( ! ect_hdr = egrep( pattern: "^Expect-CT\s*:", string: banner, icase: TRUE ) ) {
  # The 304 status code has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
  # e.g. mod_headers from Apache won't add additional headers on this code so don't complain about a missing header.
  # nb: There might be still some web servers sending the headers on a 304 status code so we're still reporting it below if there was a header included.
  if( banner !~ "^HTTP/1\.[01] 304" ) {
    set_kb_item( name: "expect-ct/missing", value: TRUE );
    set_kb_item( name: "expect-ct/missing/port", value: port );
  }
  exit( 0 );
}

ect_hdr = chomp( ect_hdr );
ect_hdr_lo = tolower( ect_hdr );

# max-age is required: http://httpwg.org/http-extensions/expect-ct.html#the-max-age-directive
# Assume a missing Expect-CT if its not specified
if( "max-age=" >!< ect_hdr_lo ) {
  set_kb_item( name: "expect-ct/missing", value: TRUE );
  set_kb_item( name: "expect-ct/missing/port", value: port );
  set_kb_item( name: "expect-ct/max_age/missing/" + port, value: TRUE );
  set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );
  exit( 0 );
}

# Assuming missing support if value is set to zero
if( "max-age=0" >< ect_hdr_lo ) {
  set_kb_item( name: "expect-ct/missing", value: TRUE );
  set_kb_item( name: "expect-ct/missing/port", value: port );
  set_kb_item( name: "expect-ct/max_age/zero/" + port, value: TRUE );
  set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );
  exit( 0 );
}

set_kb_item( name: "expect-ct/available", value: TRUE );
set_kb_item( name: "expect-ct/available/port", value: port );
set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );

if( "enforce" >!< ect_hdr_lo ) {
  set_kb_item( name: "expect-ct/enforce/missing", value: TRUE );
  set_kb_item( name: "expect-ct/enforce/missing/port", value: port );
}

ma = eregmatch( pattern: "max-age=([0-9]+)", string: ect_hdr, icase: TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name: "expect-ct/max_age/" + port, value:ma[1] );

log_message( port: port, data: 'The remote web server is sending the "Expect Certificate Transparency" header.\n\nECT-Header:\n\n' + ect_hdr );

exit( 0 );
