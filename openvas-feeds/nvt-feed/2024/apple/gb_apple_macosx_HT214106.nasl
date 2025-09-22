# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832979");
  script_version("2025-01-22T05:38:11+0000");
  script_cve_id("CVE-2024-27804", "CVE-2024-27837", "CVE-2024-27816", "CVE-2024-27825",
                "CVE-2024-27829", "CVE-2024-27841", "CVE-2024-23236", "CVE-2024-27805",
                "CVE-2024-27817", "CVE-2024-27831", "CVE-2024-27832", "CVE-2024-27827",
                "CVE-2024-27801", "CVE-2024-27836", "CVE-2024-27799", "CVE-2024-27818",
                "CVE-2024-27815", "CVE-2024-27811", "CVE-2023-42893", "CVE-2024-23251",
                "CVE-2024-23282", "CVE-2024-27810", "CVE-2024-27800", "CVE-2024-27802",
                "CVE-2024-27857", "CVE-2024-27822", "CVE-2024-27824", "CVE-2024-27885",
                "CVE-2024-27813", "CVE-2024-27844", "CVE-2024-27843", "CVE-2024-27821",
                "CVE-2024-27855", "CVE-2024-27806", "CVE-2024-27798", "CVE-2024-27848",
                "CVE-2024-27847", "CVE-2024-27842", "CVE-2024-27796", "CVE-2024-27834",
                "CVE-2024-27838", "CVE-2024-27808", "CVE-2024-27850", "CVE-2024-27851",
                "CVE-2024-27830", "CVE-2024-27820", "CVE-2024-27884", "CVE-2024-27826",
                "CVE-2024-27823", "CVE-2024-40771", "CVE-2024-27856");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 18:19:33 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 14:41:24 +0530 (Tue, 14 May 2024)");
  script_name("Apple MacOSX Security Update (HT214106)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-27798: An authorization issue

  - CVE-2024-27821: A path handling issue

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution, elevate privileges, bypass pointer
  authentication and obtain sensitive information.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.5");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214106");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.5")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
