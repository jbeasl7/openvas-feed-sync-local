# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:framemaker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826468");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2021-39835", "CVE-2021-40697", "CVE-2021-39833", "CVE-2021-39834",
                "CVE-2021-39832", "CVE-2021-39830", "CVE-2021-39829", "CVE-2021-39831",
                "CVE-2021-39862", "CVE-2021-39865");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 16:15:08 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-15 11:33:35 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Framemaker Security Updates (APSB21-74) - Windows");

  script_tag(name:"summary", value:"Adobe Framemaker is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-39835: Use After Free error.

  - CVE-2021-40697, CVE-2021-39833, CVE-2021-39834, CVE-2021-39862, CVE-2021-39865: Multiple
  out-of-bounds read errors.

  - CVE-2021-39832, CVE-2021-39830: Access of Memory Location After End of Buffer

  - CVE-2021-39829, CVE-2021-39831: An Out-of-bounds Write Error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and escalate privilege on the system.");

  script_tag(name:"affected", value:"Adobe Framemaker versions 2019 through version 2019 Update 8
  (2019.0.8) and versions 2020 prior to version 2020 Update 3 (2020.0.3).");

  script_tag(name:"solution", value:"Update to version 2019 Update 8 (2019.0.8) and apply the
  provided hotfix or version 2020 Update 3 (2020.0.3). See the referenced vendor advisory for
  additional information.

  Note: Please create an override for this result if only the hotfix was applied.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-74.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if (version_in_range_exclusive(version: version, test_version_lo: "2020.0.0", test_version_up: "2020.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2020 Update 3 (2020.0.3)", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
