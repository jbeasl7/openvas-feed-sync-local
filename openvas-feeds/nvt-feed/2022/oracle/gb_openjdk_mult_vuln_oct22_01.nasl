# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104364");
  script_version("2024-02-23T14:36:45+0000");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-10-19 11:10:25 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 21:18:00 +0000 (Tue, 18 Oct 2022)");

  script_cve_id("CVE-2022-21618", "CVE-2022-39399");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK 11, 13, 15, 17, 19 Multiple Vulnerabilities (Oct 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the
  vulnerabilities.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 11, 13, 15, 17 and 19.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2022-10-18");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2022-October/000017.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (vers =~ "^11\." && version_is_less(version: vers, test_version: "11.0.17")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.0.17", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^13\." && version_is_less(version: vers, test_version: "13.0.13")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "13.0.13", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^15\." && version_is_less(version: vers, test_version: "15.0.9")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "15.0.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^17\." && version_is_less(version: vers, test_version: "17.0.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "17.0.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^19\." && version_is_less(version: vers, test_version: "19.0.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "19.0.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
