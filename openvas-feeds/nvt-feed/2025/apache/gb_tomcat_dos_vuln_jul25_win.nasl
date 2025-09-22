# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154918");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  #     fixed versions. The original creation_date has been kept.
  script_tag(name:"creation_date", value:"2025-07-09 03:13:55 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-52434");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Jul 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A race condition on connection close could trigger a JVM crash
  when using the APR/Native connector leading to a DoS. This was particularly noticeable with
  client initiated closes of HTTP/2 connections.");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.106 and prior.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that all versions prior to 9.x are affected by these flaws.
  If you disagree with this assessment and want to accept the risk please create an override for
  this result.");

  script_tag(name:"solution", value:"Update to version 9.0.107 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/gxgh65004f25y8519coth6w7vchww030");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.107");

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

if (version_is_less_equal(version: version, test_version: "9.0.106")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.107", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
