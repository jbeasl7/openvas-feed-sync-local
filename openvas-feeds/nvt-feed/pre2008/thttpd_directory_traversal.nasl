# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:acme:thttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14229");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10862");
  script_xref(name:"OSVDB", value:"8372");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("thttpd Directory Traversal Vulnerability (CVE-2004-2628) - Windows");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("gb_thttpd_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("thttpd/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"The remote web server is vulnerable to a path traversal vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to read arbitrary files on the remote
  system with the privileges of the http process.");

  script_tag(name:"solution", value:"Upgrade your web server or change it.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files( "windows" );

foreach file (keys(files)) {
  url = "c:\" + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
