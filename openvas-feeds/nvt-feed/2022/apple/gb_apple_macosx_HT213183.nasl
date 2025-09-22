# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819818");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2022-22633", "CVE-2022-22669", "CVE-2022-22665", "CVE-2022-22631",
                "CVE-2022-22625", "CVE-2022-22648", "CVE-2022-22626", "CVE-2022-22627",
                "CVE-2022-22597", "CVE-2021-22946", "CVE-2021-22947", "CVE-2022-22582",
                "CVE-2021-22945", "CVE-2022-22623", "CVE-2022-22643", "CVE-2022-22611",
                "CVE-2022-22612", "CVE-2022-22661", "CVE-2022-22641", "CVE-2022-22613",
                "CVE-2022-22614", "CVE-2022-22615", "CVE-2022-22632", "CVE-2022-22638",
                "CVE-2022-22640", "CVE-2021-36976", "CVE-2022-22647", "CVE-2022-22656",
                "CVE-2022-22657", "CVE-2022-22664", "CVE-2022-22644", "CVE-2022-22617",
                "CVE-2022-22609", "CVE-2022-22650", "CVE-2022-22616", "CVE-2022-22600",
                "CVE-2022-22599", "CVE-2022-22651", "CVE-2022-22639", "CVE-2022-22660",
                "CVE-2022-22621", "CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4173",
                "CVE-2021-4187", "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-46059",
                "CVE-2022-0128", "CVE-2022-0156", "CVE-2022-0158", "CVE-2021-30918",
                "CVE-2022-22662", "CVE-2022-22610", "CVE-2022-22624", "CVE-2022-22628",
                "CVE-2022-22629", "CVE-2022-22637", "CVE-2022-22668", "CVE-2021-30977",
                "CVE-2022-21658", "CVE-2022-22663", "CVE-2022-22672", "CVE-2022-26688",
                "CVE-2022-26690", "CVE-2022-26691", "CVE-2022-22630");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 17:51:00 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-03-17 11:44:49 +0530 (Thu, 17 Mar 2022)");
  script_name("Apple Mac OS X Security Update (HT213183)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of symlinks.

  - An improper access restrictions.

  - An improper state management.

  - An improper memory management.

  - An improper bounds checking.

  - An input validation error.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  conduct arbitrary code execution, gain elevated privileges, perform a denial of
  service attack, leak sensitive user information etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.3.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Monterey version
  12.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213183");
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

if(version_in_range(version:osVer, test_version:"12.0", test_version2:"12.2.1"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.3");
  security_message(data:report);
  exit(0);
}
exit(99);
