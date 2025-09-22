# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834815");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-49065", "CVE-2024-49069");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 02:04:30 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 17:50:22 +0530 (Wed, 11 Dec 2024)");
  script_name("Microsoft Office Multiple Vulnerabilities (Dec24) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office on Mac OSX according to Microsoft security
  update November 2024");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-49065: Microsoft Office Remote Code Execution Vulnerability.

  - CVE-2024-49069: Microsoft Excel Remote Code Execution Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Office 2021 prior to version 16.92 (Build 24120731).");

  script_tag(name:"solution", value:"Update to version 16.92 (Build 24120731)
  or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("MS/Office/MacOSX/Ver"))
  exit(0);


if(vers =~ "^16\.") {
  if(version_in_range(version:vers, test_version:"16.79.0", test_version2:"16.91.1")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.92 (Build 24120731)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
