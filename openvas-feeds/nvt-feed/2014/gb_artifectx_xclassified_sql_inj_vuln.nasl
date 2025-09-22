# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804684");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-4741");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-07-21 11:57:35 +0530 (Mon, 21 Jul 2014)");
  script_name("Artifectx xClassified 'catid' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Artifectx xClassified is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the 'ads.php' script not properly sanitizing user-supplied input
  to the 'catid' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Artifectx XClassified version 1.2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68438");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/ads", "/classifieds", "/artifectx", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if (">xClassified Web" >< rcvRes && "artifectx" >< rcvRes)
  {
    url = dir + "/ads.php?catid=1'SQL-Injection-Test" ;

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"SQL-Injection-Test",
       extra_check: make_list("Artifectx", ">Login<")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
