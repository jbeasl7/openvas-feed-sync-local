# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821277");
  script_version("2025-07-25T05:44:05+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-32784", "CVE-2022-32792", "CVE-2022-2294");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-27 19:32:00 +0000 (Tue, 27 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-07-22 14:48:43 +0530 (Fri, 22 Jul 2022)");
  script_name("Apple Safari Security Update (HT213341)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities according to Apple security advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A memory corruption issue due to an improper state management.

  - An out-of-bounds write issue due to improper input validation.

  - Improper UI handling.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution and leak sensitive data.");

  script_tag(name:"affected", value:"Apple Safari versions before 15.6");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 15.6 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213341");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^10\.15\." && osVer !~ "^11\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"15.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
