# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:framemaker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817972");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2021-21056");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-12 19:15:13 +0000 (Fri, 12 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-16 17:12:29 +0530 (Tue, 16 Mar 2021)");
  script_name("Adobe Framemaker Security Updates (APSB20-54) - Windows");

  script_tag(name:"summary", value:"Adobe Framemaker is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the system.");

  script_tag(name:"affected", value:"Adobe Framemaker versions 2019 through version 2019 Update 8
  (2019.0.8) and versions 2020 through version 2020 Update 1 (2020.0.1).");

  script_tag(name:"solution", value:"Update to version 2019 Update 8 (2019.0.8), version 2020
  Update 1 (2020.0.1) and apply the provided hotfix. See the referenced vendor advisory for
  additional information.

  Note: Please create an override for this result if only the hotfix was applied.");


  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if (version_in_range(version: version, test_version: "2019.0.0", test_version2: "2019.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2020.0.0", test_version2: "2020.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
