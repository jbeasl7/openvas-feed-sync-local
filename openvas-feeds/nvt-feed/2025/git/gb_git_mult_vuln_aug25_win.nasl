# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:git:git";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836565");
  script_version("2025-08-12T05:40:06+0000");
  script_cve_id("CVE-2024-32002", "CVE-2024-32004", "CVE-2024-32020", "CVE-2024-32021",
                "CVE-2024-32465");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 20:40:28 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2025-08-05 16:03:11 +0530 (Tue, 05 Aug 2025)");
  script_name("Git Multiple Vulnerabilities (Aug 2025) - Windows");

  script_tag(name:"summary", value:"Git is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass checks and execute remote code.");

  script_tag(name:"affected", value:"Git prior to version 2.39.4, 2.40.x before 2.40.2,
  2.41.0, 2.42.x before 2.42.2, 2.43.x before 2.43.4, 2.44.0 and 2.45.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.39.4 or 2.40.2 or 2.41.1
  or 2.42.2 or 2.43.4 or 2.44.1 or 2.45.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.wiz.io/vulnerability-database/cve/cve-2024-32002");
  script_xref(name:"URL", value:"https://www.wiz.io/vulnerability-database/cve/cve-2024-32004");
  script_xref(name:"URL", value:"https://www.wiz.io/vulnerability-database/cve/cve-2024-32021");
  script_xref(name:"URL", value:"https://www.wiz.io/vulnerability-database/cve/cve-2024-32465");
  script_xref(name:"URL", value:"https://www.wiz.io/vulnerability-database/cve/cve-2024-32020");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.39.4")) {
  fix = "2.39.4";
}

if(version_in_range_exclusive(version: vers, test_version_lo: "2.40.0", test_version_up: "2.40.2")) {
  fix = "2.40.2";
}

if(version_is_equal(version:vers, test_version:"2.41.0")) {
  fix = "2.41.1";
}

if(version_in_range_exclusive(version: vers, test_version_lo: "2.42.0", test_version_up: "2.42.2")) {
  fix = "2.42.2";
}

if(version_in_range_exclusive(version: vers, test_version_lo: "2.43.0", test_version_up: "2.43.4")) {
  fix = "2.43.4";
}

if(version_is_equal(version:vers, test_version:"2.44.0")) {
  fix = "2.44.1";
}

if(version_is_equal(version:vers, test_version:"2.45.0")) {
  fix = "2.45.1";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);