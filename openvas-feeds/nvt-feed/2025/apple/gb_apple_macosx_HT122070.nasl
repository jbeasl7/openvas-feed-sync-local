# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834918");
  script_version("2025-05-21T05:40:19+0000");
  script_cve_id("CVE-2025-24109", "CVE-2025-24100", "CVE-2025-24114", "CVE-2025-24121",
                "CVE-2025-24122", "CVE-2025-24127", "CVE-2025-24106", "CVE-2024-44172",
                "CVE-2025-24123", "CVE-2025-24124", "CVE-2025-24102", "CVE-2025-24174",
                "CVE-2025-24086", "CVE-2025-24094", "CVE-2025-24115", "CVE-2025-24116",
                "CVE-2025-24136", "CVE-2025-24130", "CVE-2025-24146", "CVE-2025-24099",
                "CVE-2024-54497", "CVE-2025-24093", "CVE-2025-24149", "CVE-2025-24103",
                "CVE-2025-24139", "CVE-2025-24151", "CVE-2025-24138", "CVE-2025-24176",
                "CVE-2025-24154", "CVE-2025-24120", "CVE-2025-24156", "CVE-2025-24185",
                "CVE-2025-24183");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-03 22:51:48 +0000 (Mon, 03 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-01-28 10:51:39 +0530 (Tue, 28 Jan 2025)");
  script_name("Apple MacOSX Security Update (HT122070)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, elevate privileges, bypass
  security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version
  13.7.3.");

  script_tag(name:"solution", value:"Update macOS Ventura to version 13.7.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/122070");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"13.7.3")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.7.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
