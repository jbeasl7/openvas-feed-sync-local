# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149061");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-01-04 02:21:06 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-10 03:40:00 +0000 (Tue, 10 Jan 2023)");

  script_cve_id("CVE-2022-45143");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat JsonErrorReportValve Injection Vulnerability (Jan 2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a JsonErrorReportValve injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The JsonErrorReportValve did not escape the type, message or
  description values. In some circumstances these are constructed from user provided data and it
  was therefore possible for users to supply values that invalidated or manipulated the JSON
  output.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.83 only, 9.0.40 through 9.0.68 and
  10.1.0-M1 through 10.1.1.");

  script_tag(name:"solution", value:"Update to version 8.5.84, 9.0.69, 10.1.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/yqkd183xrw3wqvnpcg3osbcryq85fkzj");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.2");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.69");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.84");

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

# nb: As e.g. "9.0.40" as the lowest affected version for 9.x or "8.5.83 only" is mentioned in the
# advisory we're following strictly* the advisory versions because e.g. the affected code might not
# have been introduced in older 10.0.x releases not mentioned.
#
# * unlike for others where the vendor might just haven't mentioned 10.0.x as affected because it is
# already EOL

if (version_is_equal(version: version, test_version: "8.5.83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.84", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.40", test_version_up: "9.0.69")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.69", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0.M1", test_version_up: "10.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
