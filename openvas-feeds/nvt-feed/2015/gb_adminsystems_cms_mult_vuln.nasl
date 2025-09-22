# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805292");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-1603", "CVE-2015-1604");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-02-27 11:02:30 +0530 (Fri, 27 Feb 2015)");
  script_name("Adminsystems CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Adminsystems CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as,

  - The upload action in the files.php script does not properly verify or
    sanitize user-uploaded files via the 'path' parameter.

  - The index.php script does not validate input to the 'page' parameter
    before returning it to users.

  - The /asys/site/system.php script does not validate input to the 'id'
    parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary PHP code and execute arbitrary script code in
  a user's browser session within the trust relationship between their browser
  and the server.");

  script_tag(name:"affected", value:"Adminsystems CMS before 4.0.2");

  script_tag(name:"solution", value:"Upgrade to Adminsystems CMS version 4.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72605");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/50");
# 2016-06-21: 404
#  script_xref(name:"URL", value:"http://sroesemann.blogspot.de/2015/02/report-for-advisory-sroeadv-2015-14.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"https://github.com/kneecht/adminsystems");
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

foreach dir (make_list_unique("/", "/adminsystems", "/cms", "/adminsystemscms", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:http_port);

  if(rcvRes && rcvRes =~ ">Powered by.*>Adminsystems<")
  {
    url = dir + '/index.php?page="><script>alert(document.cookie)</script>&lang';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>",
       extra_check:">Adminsystems<"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
