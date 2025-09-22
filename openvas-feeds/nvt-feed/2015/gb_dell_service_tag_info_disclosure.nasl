# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105475");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-12-03 10:52:22 +0100 (Thu, 03 Dec 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell Foundation Services <= 2.3.3800.0A00 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 7779);
  script_mandatory_keys("Microsoft-HTTPAPI/banner");

  script_tag(name:"summary", value:"An issue in Dell Foundation Services, version 2.3.3800.0A00 and
  below, can be exploited by a malicious website to leak the Dell service tag of a Dell system,
  which can be used for tracking purposes, or for social engineering.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Dell Foundation Services starts a HTTPd that listens on port
  7779. Generally, requests to the API exposed by this HTTPd must be requests signed using a
  RSA-1024 key and hashed with SHA512. One of the JSONP API endpoints to obtain the service tag
  does not need a valid signature to be provided. Thus, any website can call it.");

  script_tag(name:"affected", value:"Dell Foundation Services version 2.3.3800.0A00 and prior.");

  script_tag(name:"solution", value:"Update to a higher version or uninstall Dell Foundation
  Services.");

  script_xref(name:"URL", value:"http://lizardhq.rum.supply/2015/11/25/dell-foundation-services.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:7779 );

banner = http_get_remote_headers( port:port );

if( ! banner || "Microsoft-HTTPAPI" >!< banner || banner !~ "^HTTP/1\.[01] 404" )
  exit( 0 );

url = "/Dell%20Foundation%20Services/eDell/IeDellCapabilitiesApi/REST/ServiceTag";

buf = http_get_cache( port:port, item:url );

if( buf =~ "^HTTP/1\.[01] 200" && "application/json" >< buf ) {
  hb = split( buf, sep:'\r\n\r\n', keep:FALSE );
  if( isnull( hb[1] ) )
    exit( 0 );

  body = str_replace( string: hb[1], find:'\r\n', replace:'' );

  if( body =~ '^"[A-Za-z0-9]+"$' ) {
    rep = http_report_vuln_url( port:port, url:url );
    rep += '\nDell Service Tag: ' + body;

    security_message( port:port, data:rep );
    exit( 0 );
  }
}

exit( 99 );
