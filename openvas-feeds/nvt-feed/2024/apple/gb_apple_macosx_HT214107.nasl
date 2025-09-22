# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832980");
  script_version("2025-01-22T05:38:11+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-27805", "CVE-2024-27817", "CVE-2024-27831", "CVE-2024-27827",
                "CVE-2024-27789", "CVE-2024-27799", "CVE-2024-27840", "CVE-2023-42861",
                "CVE-2024-27810", "CVE-2024-27800", "CVE-2024-27802", "CVE-2024-27885",
                "CVE-2024-27824", "CVE-2024-23296", "CVE-2024-27843", "CVE-2024-27855",
                "CVE-2024-27806", "CVE-2024-27798", "CVE-2024-27847", "CVE-2024-27796",
                "CVE-2024-27823", "CVE-2024-40771");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-03 16:12:55 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 14:55:16 +0530 (Tue, 14 May 2024)");
  script_name("Apple MacOSX Security Update (HT214107)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-27789: An information disclosure vulnerability

  - CVE-2024-23296: A memory corruption vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution, information disclosure and denial of
  service.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version
  13.6.7.");

  script_tag(name:"solution", value:"Update macOS Ventura to version 13.6.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214107");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.6.7")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.6.7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
