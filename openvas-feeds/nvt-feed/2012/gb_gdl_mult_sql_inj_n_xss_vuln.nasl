# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802433");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-06-01 13:02:10 +0530 (Fri, 01 Jun 2012)");
  script_name("Ganesha Digital Library Multiple SQLi and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploits/18392");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18953/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113132/ganesha-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal cookie
  based authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Ganesha Digital Library 4.0 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via the 'm' parameter to office.php, the 'id' parameter
  to publisher.php, and the 's' parameter to search.php is not properly
  sanitised before being returned to the user.

  - Input passed via the 'node' parameter to go.php is not properly
  sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Ganesha Digital Library is prone to multiple SQL injection (SQLi)
  and cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/GDL", http_cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && ">KBPublisher<" >< res && "<title>Welcome - ACME Digital Library -  GDL" >< res ) {

    url = dir + "/publisher.php?id='mehaha!!!";

    if(http_vuln_check( port: port, url: url, check_header: TRUE,
       pattern: ">You have an error in your SQL syntax near 'mehaha!!!'",
       extra_check: ">PublisherID:</"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
