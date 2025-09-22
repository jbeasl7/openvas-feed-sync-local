# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126890");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-08-13 08:27:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 21:42:20 +0000 (Wed, 04 Sep 2024)");

  script_cve_id("CVE-2023-31493", "CVE-2023-41884", "CVE-2024-43358", "CVE-2024-43359",
                "CVE-2024-43360");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder < 1.36.34 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_http_detect.nasl");
  script_mandatory_keys("zoneminder/detected");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-31493: Remote code execution (RCE) in Logging

  - CVE-2023-41884: Improper neutralization of special elements used in an SQL Command in
  watch.php can lead to SQL injection (SQLi).

  - CVE-2024-43358: Cross-site scirpting (XSS) in filter view

  - CVE-2024-43359: Cross-site scirpting (XSS) in montagereview

  - CVE-2024-43360: Time-based SQL Injection can be triggered by the sort parameter of the
  /zm/index.php endpoint. An attacker can damage all data, cause repudiation issues, and dump all
  the probable databases");

  script_tag(name:"affected", value:"ZoneMinder prior to version 1.36.34.");

  script_tag(name:"solution", value:"Update to version 1.36.34 or later.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/releases/tag/1.36.34");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-rpwp-cr82-f2p3");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-2qp3-fwpv-mc96");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-6rrw-66rf-6g5f");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-pjjm-3qxp-6hj8");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-9cmr-7437-v9fj");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.36.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
