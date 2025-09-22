# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819977");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-22586", "CVE-2022-22584", "CVE-2022-22585", "CVE-2022-22578",
                "CVE-2022-22591", "CVE-2022-22587", "CVE-2022-22593", "CVE-2022-22579",
                "CVE-2022-22583", "CVE-2022-22589", "CVE-2022-22590", "CVE-2022-22592",
                "CVE-2022-22594");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-28 16:50:00 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-01-31 08:48:29 +0530 (Mon, 31 Jan 2022)");
  script_name("Apple Mac OS X Security Update (HT213054)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An out-of-bounds write issue due to improper bounds checking.

  - Multiple memory corruption issues due to improper input validation.

  - Multiple state management errors.

  - An inherited permissions issue.

  - A cross-origin issue in the IndexDB API.

  - An issue existed within the path validation logic for symlinks");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, privilege escalation, restricted file
  access, cross site scripting and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.2.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Monterey version
  12.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"12.0", test_version2:"12.1"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.2");
  security_message(data:report);
  exit(0);
}
exit(99);
