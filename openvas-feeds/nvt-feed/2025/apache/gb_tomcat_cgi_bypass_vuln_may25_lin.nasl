# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154590");
  script_version("2025-05-30T15:42:19+0000");
  script_tag(name:"last_modification", value:"2025-05-30 15:42:19 +0000 (Fri, 30 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-30 02:33:47 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-46701");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat CGI Security Constraint Bypass Vulnerability (May 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a CGI security constraint bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When running on a case insensitive file system with security
  constraints configured for the <code>pathInfo</code> component of a URL that mapped to the CGI
  servlet, it is possible to bypass those security constraints with a specially crafted URL.");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.104 and prior, 10.x through
  10.1.40 and 11.0.0-M1 through 11.0.6.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that the whole 10.x branch and all versions prior to 9.x are affected by these flaws.
  If you disagree with this assessment and want to accept the risk please create an override for
  this result.");

  script_tag(name:"solution", value:"Update to version 9.0.105, 10.1.41, 11.0.7 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/xhqqk9w5q45srcdqhogdk04lhdscv30j");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "9.0.104")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.105", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
