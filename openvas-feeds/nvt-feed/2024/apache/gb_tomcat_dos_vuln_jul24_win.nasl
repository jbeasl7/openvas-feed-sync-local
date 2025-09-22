# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152544");
  script_version("2024-12-19T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-12-19 05:05:34 +0000 (Thu, 19 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-07-04 02:12:07 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-34750");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Jul 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When processing an HTTP/2 stream, Tomcat did not handle some
  cases of excessive HTTP headers correctly. This led to a miscounting of active HTTP/2 streams
  which in turn led to the use of an incorrect infinite timeout which allowed connections to remain
  open which should have been closed.");

  script_tag(name:"affected", value:"Apache Tomcat versions prior to 9.0.90, 10.x through 10.1.24
  and 11.0.0-M1 through 11.0.0-M20.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it is
  assumed that the whole 10.x branch and all versions prior to 9.x are affected by this flaw. If you
  disagree with this assessment and want to accept the risk please create an override for this
  result.");

  script_tag(name:"solution", value:"Update to version 9.0.90, 10.1.25, 11.0.0-M21 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/4kqf0bc9gxymjc2x7v3p7dvplnl77y8l");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M21");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.25");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.90");

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

if (version_is_less(version: version, test_version: "9.0.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.90", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.0.M21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
