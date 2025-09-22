# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sysaid:sysaid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106006");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2995");

  script_name("SysAid < 15.2 Unauthenticated File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sysaid_help_desk_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("sysaid/http/detected");

  script_tag(name:"summary", value:"SysAid Help Desktop Software is prone to a unauthenticated file
  upload vulnerability.");

  script_tag(name:"vuldetect", value:"- Sends a crafted HTTP GET request and checks the response.

  - Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists in the RdsLogsEntry servlet which
  accepts unauthenticated file uploads and handles zip file contents in an insecure way. Note that
  this will only work if the target is running Java 6 or 7 up to 7u25, as Java 7u40 and above
  introduce a protection against null byte injection in file names.");

  script_tag(name:"impact", value:"An unauthenticated attacker can upload arbitrary files which
  could lead to remote code execution.");

  script_tag(name:"affected", value:"SysAid Help Desktop version 15.1.x and prior.");

  script_tag(name:"solution", value:"Update to version 15.2 or later.");

  script_xref(name:"URL", value:"https://www.security-database.com/detail.php?alert=CVE-2015-2995");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
dir = infos["location"];

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

url = dir + "/rdslogs?rdsName=" + rand_str(length: 4);
req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n\r\n');
buf = http_keepalive_send_recv(port: port, data: req);

if (buf =~ "^HTTP/1\.[01] 200" && version_is_less(version: vers, test_version: "15.2")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "15.2", install_path: dir);
  report += '\n' + http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
