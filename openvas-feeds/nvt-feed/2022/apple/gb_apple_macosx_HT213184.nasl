# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819819");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2022-22633", "CVE-2022-22631", "CVE-2022-22648", "CVE-2022-22627",
                "CVE-2022-22626", "CVE-2022-22625", "CVE-2022-22597", "CVE-2022-22616",
                "CVE-2022-22661", "CVE-2022-22613", "CVE-2022-22614", "CVE-2022-22615",
                "CVE-2022-22638", "CVE-2022-22632", "CVE-2022-22647", "CVE-2022-22656",
                "CVE-2022-22617", "CVE-2022-22650", "CVE-2022-22599", "CVE-2022-22662",
                "CVE-2022-22582");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 18:06:00 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-17 11:44:49 +0530 (Thu, 17 Mar 2022)");
  script_name("Apple Mac OS X Security Update (HT213184)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A validation issue existed in the handling of symlinks.

  - Multiple state management errors.

  - An improper input validation.

  - An improper bounds checking.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, denial of service, privilege escalation
  and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213184");
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
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.4"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.5");
  security_message(data:report);
  exit(0);
}
exit(99);
