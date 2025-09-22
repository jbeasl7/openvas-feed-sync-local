# SPDX-FileCopyrightText: 2004 Astharot
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12042");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2175");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SQL injection in ReviewPost PHP Pro");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Astharot");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.zone-h.org/advisories/read/id=3864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9574");
  script_xref(name:"URL", value:"http://www.photopost.com/members/forum/showthread.php?s=&threadid=98098");

  script_tag(name:"solution", value:"Download the vendor supplied patch linked in the references.");

  script_tag(name:"summary", value:"There is a flaw in ReviewPost PHP Pro which may allow a malicious
  attacker to inject arbitrary SQL queries which allows it to fetch data from the database.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/showproduct.php?product=1'";
  if( http_vuln_check( port:port, url:url, pattern:"id,user,userid,cat,date,title,description,manu,keywords,bigimage,bigimage2,bigimage3,views,approved,rating" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  url = dir + "/showcat.php?cat=1'";
  if( http_vuln_check( port:port, url:url, pattern:"id,catname FROM rp_categories" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
