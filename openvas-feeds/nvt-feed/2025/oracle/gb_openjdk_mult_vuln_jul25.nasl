# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119066");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-16 09:51:10 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:47 +0000 (Tue, 15 Jul 2025)");

  script_cve_id("CVE-2025-30749", "CVE-2025-50106", "CVE-2025-30754");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK 8.x - 24.x Multiple Vulnerabilities (Jul 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected component(s):

  - CVE-2025-30749, CVE-2025-50106: client-libs/2d

  - CVE-2025-30754: security-libs/javax.net.ssl

  Please see the referenced CVEs for more details on the flaws.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 8.x through 24.x.

  Note: The vendor is only evaluating the affected status of supported versions but EOL versions
  like 9.x, 12.x or 18.x in between the affected versions are also assumed to be affected.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2025-07-15");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2025-July/000028.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.8.0", test_version2: "1.8.0.452")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.462 (8u462)", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "11.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "17.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "21.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "22.0", test_version2: "24.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
