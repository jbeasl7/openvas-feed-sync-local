# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103352");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-12-02 11:09:47 +0100 (Fri, 02 Dec 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-4335");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Contao CMS <= 2.10.1 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Contao is prone to a cross-site scripting (XSS) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Contao CMS version 2.10.1 and probably prior.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50061");
  script_xref(name:"URL", value:"http://dev.contao.org/projects/typolight/repository/revisions/1041");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520046");
  script_xref(name:"URL", value:"http://www.rul3z.de/advisories/SSCHADV2011-025.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port:port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/contao", "/cms", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if (!res || res !~ "^HTTP/1\.[01] 200" || ("teachers.html" >!< res && "academy.html" >!< res))
    continue;

  url = dir + '/index.php/teachers.html?"/><script>alert(/' + vt_strings["lowercase"] + '/)</script>';

  if (http_vuln_check(port: port, url: url, check_header:TRUE,
                      pattern: "<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",
                      extra_check: "This website is powered by Contao")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
