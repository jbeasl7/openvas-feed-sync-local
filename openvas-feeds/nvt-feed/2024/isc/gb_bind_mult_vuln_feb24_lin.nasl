# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151715");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-14 03:51:53 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Multiple DoS Vulnerabilities (CVE-2023-50387, CVE-2023-50868, KeyTrap) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-50387: KeyTrap - Extreme CPU consumption in DNSSEC validator

  - CVE-2023-50868: Preparing an NSEC3 closest encloser proof can exhaust CPU resources");

  script_tag(name:"affected", value:"ISC BIND version 9.0.0 through 9.16.46, 9.18.0 through
  9.18.22, 9.19.0 through 9.19.20, 9.9.3-S1 through 9.16.46-S1 and 9.18.11-S1 through 9.18.22-S1.");

  script_tag(name:"solution", value:"Update to version 9.16.48, 9.18.24, 9.19.21, 9.16.48-S1,
  9.18.24-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-50387");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2023-50868");
  script_xref(name:"URL", value:"https://www.athene-center.de/en/keytrap");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version =~ "^9\.[0-9]+\.[0-9]+s[0-9]") {
  if (version_in_range(version: version, test_version: "9.9.3s1", test_version2: "9.16.46s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.48-S1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.18.11s1", test_version2: "9.18.22s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.18.24-S1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.16.46")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.48", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.18.0", test_version2: "9.18.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.18.24", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.19.0", test_version2: "9.19.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.19.21", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
