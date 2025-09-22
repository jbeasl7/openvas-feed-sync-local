# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140695");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-17 15:42:36 +0700 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 18:19:00 +0000 (Wed, 21 Jun 2023)");

  script_cve_id("CVE-2017-3145");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability (Jan 2017) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"BIND is improperly sequencing cleanup operations on upstream recursion fetch
  contexts, leading in some cases to a use-after-free error that can trigger an assertion failure and crash in
  named.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND 9.9.9-P8 to 9.9.11, 9.10.4-P8 to 9.10.6, 9.11.0-P5 to 9.11.2,
  9.9.9-S10 to 9.9.11-S1, 9.10.5-S1 to 9.10.6-S1, and 9.12.0a1 to 9.12.0rc1.");

  script_tag(name:"solution", value:"Update to version 9.9.11-S2, 9.10.6-S2, 9.9.11-P1, 9.10.6-P1, 9.11.2-P1,
  9.12.0rc2 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01542");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "^9\.(9|10)\.[0-9]s[0-9]") {
  if (version_in_range(version: version, test_version: "9.9.9s10", test_version2: "9.9.11s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.11-S2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.5s1", test_version2: "9.10.6s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.6-S2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.9.9p8", test_version2: "9.9.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.11-P1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.4p8", test_version2: "9.10.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.6.P1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.11.0p5", test_version2: "9.11.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.2-P1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if ((revcomp(a: version, b: "9.12.0a1") >= 0) && (revcomp(a: version, b: "9.12.0rc2") < 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.12.0rc2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
