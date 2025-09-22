# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15466");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2004-1570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11303");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("bBlog SQL injection flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 0.7.4 or newer.");

  script_tag(name:"summary", value:"The remote server runs a version of bBlog which is as old as or
  older than version 0.7.4.");

  script_tag(name:"insight", value:"The remote version of this software is affected by a SQL injection
  attacks in the script 'rss.php'. This issue is due to a failure of the application to properly
  sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may use these flaws to execute arbitrary PHP code on this
  host or to take the control of the remote database.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/bblog", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = string(dir,"/index.php");
  r = http_get_cache(item:url, port:port);
  if(!r)
    continue;

  if(egrep(pattern:"www\.bBlog\.com target=.*bBlog 0\.([0-6]\.|7\.[0-3][^0-9]).*&copy;", string:r))
    security_message(port:port);
}

exit( 99 );
