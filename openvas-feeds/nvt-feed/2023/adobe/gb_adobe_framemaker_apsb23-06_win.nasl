# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:framemaker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826928");
  script_version("2024-10-29T05:05:46+0000");
  script_cve_id("CVE-2023-21584", "CVE-2023-21619", "CVE-2023-21620", "CVE-2023-21621",
                "CVE-2023-21622");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-17 22:15:00 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 12:12:21 +0530 (Thu, 16 Feb 2023)");
  script_name("Adobe Framemaker Security Update (APSB23-06) - Windows");

  script_tag(name:"summary", value:"Adobe Framemaker is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-21584: An use after free error

  - CVE-2023-21620: An out-of-bounds read error

  - CVE-2023-21619, CVE-2023-21622: Multiple out-of-bounds write errors

  - CVE-2023-21621: An input validation error");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and leak memory on the system.");

  script_tag(name:"affected", value:"Adobe Framemaker versions 2020 prior to version 2020 Update 5
  (2020.0.5) and versions 2022 prior to version 2022 Update 1 (2022.0.1).");

  script_tag(name:"solution", value:"Update to version 2020 Update 5 (2020.0.5), version 2022
  Update 1 (2022.0.1) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb23-06.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_framemaker_detect_win.nasl");
  script_mandatory_keys("adobe/framemaker/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2020.0.0", test_version_up: "2020.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2020 Update 5 (2020.0.5)", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2022.0.0", test_version_up: "2022.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2022 Update 1 (2022.0.1)", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
