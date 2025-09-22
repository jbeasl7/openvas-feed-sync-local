# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16121");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("b2Evolution title SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/13718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12179");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1012797");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/18762");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"There is an SQL injection vulnerability in the remote version of b2evolution
  which may allow an attacker to execute arbitrary SQL statements against the remote database by providing
  a malformed value to the 'title' argument of index.php.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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

  if( dir == "/" ) dir = "";
  url = dir + "/index.php?blog=1&title='&more=1&c=1&tb=1&pb=1";

  if( http_vuln_check( port:port, url:url, pattern:"SELECT DISTINCT ID, post_author, post_issue_date" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
