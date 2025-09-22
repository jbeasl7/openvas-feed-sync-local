# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805262");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-1364", "CVE-2015-1363");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-29 16:47:29 +0530 (Thu, 29 Jan 2015)");
  script_name("ArticleFR CMS Multiple Vulnerabilities (Jan 2015)");

  script_tag(name:"summary", value:"ArticleFR CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'username' parameter
  to register and 'q' parameter to search/v/ is not properly sanitised before
  being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database and execute
  arbitrary HTML and script code in a users browser session in the context of an
  affected site.");

  script_tag(name:"affected", value:"ArticleFR CMS version 3.0.5, Prior
  versions may also be affected.");

  script_tag(name:"solution", value:"Upgrade to 3.0.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35857");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130066");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/81");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/101");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://articlefr.cf");
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

foreach dir (make_list_unique("/", "/articleFR", "/cms", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if (rcvRes && rcvRes =~ "Powered by.*>ArticleFR")
  {
    url = dir + "/search/v/?q=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\)</script>",
                   extra_check:"Powered by.*>ArticleFR"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
