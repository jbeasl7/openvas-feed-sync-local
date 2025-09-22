# SPDX-FileCopyrightText: 2005 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19947");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-3063");
  script_name("MailGust SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"A vulnerability was identified in MailGust, which may be
  exploited by remote attackers to execute arbitrary SQL commands.");

  script_xref(name:"URL", value:"http://retrogod.altervista.org/maildisgust.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14933");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port))
  exit(0);

foreach dir( make_list_unique( "/mailgust", "/forum", "/maillist", "/gust", http_cgi_dirs( port:port ) ) ) {

  if(dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(item:url, port:port);
  if(!res)
    continue;

  if(egrep(pattern:">Powered by <a href=[^>]+>Mailgust", string:res)) {

    host = http_host_name( port:port );

    req = string("POST ", url, " HTTP/1.0\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Length: 64\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                 "method=remind_password&list=maillistuser&email='&showAvatar=\r\n\r\n");
    recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(!recv)
      continue;

    if(egrep(pattern: "SELECT.*FROM.*WHERE", string:recv)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
