# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103530");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_name("Tickets CAD Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20268/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54803");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-08-06 12:26:58 +0200 (Mon, 06 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Tickets CAD is prone to multiple vulnerabilities.

1. A Reflected XSS vulnerability exists in the search function, search.php within the application.

2. A Stored XSS vulnerability exists in log.php while creating a new log entry.

3. Information disclosure exist which allows users even the guest account to view the tables of the sql database.");

  script_tag(name:"affected", value:"Tickets CAD 2.20G is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/tickets", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/main.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && "Welcome to Tickets" >< buf ) {

    co = eregmatch(pattern:"Set-Cookie: ([^;]+)", string:buf);
    if(isnull(co[1]))exit(0);

    c = co[1];
    host = http_host_name( port:port );

    ex = 'frm_user=guest&frm_passwd=guest&frm_daynight=Day&frm_referer=http%3A%2F%2F' + host  + '%2FDAC213%2Ftop.php';
    len = strlen(ex);

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Cookie: ", c,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 ex);
    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(result =~ "HTTP/1.. 302" && "main.php?log_in=1" >< result) {

      url = dir + '/tables.php';

      req = string("GET ",url," HTTP/1.1\r\n",
                   "Host: ", host,"\r\n",
                   "Cookie: ", c,"\r\n",
                   "\r\n");
      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if("Available 'tickets ' tables" >< result && 'submit();"> user' >< result) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
