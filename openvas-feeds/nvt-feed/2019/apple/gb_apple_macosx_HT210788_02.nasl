# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815875");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8837", "CVE-2019-8848", "CVE-2019-8842", "CVE-2019-8839",
                "CVE-2019-8830", "CVE-2019-8851", "CVE-2019-8833", "CVE-2019-8828",
                "CVE-2019-8838", "CVE-2019-8847", "CVE-2019-8852", "CVE-2019-15903",
                "CVE-2012-1164", "CVE-2012-2668", "CVE-2013-4449", "CVE-2015-1545",
                "CVE-2019-13057", "CVE-2019-13565", "CVE-2019-8832", "CVE-2017-16808",
                "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462",
                "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466",
                "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470",
                "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882",
                "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230",
                "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452",
                "CVE-2019-15166", "CVE-2019-15167");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 19:47:00 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-12-12 11:00:05 +0530 (Thu, 12 Dec 2019)");
  script_name("Apple Mac OS X Security Updates (HT210788)-02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple memory corruption issues related to an improper memory handling.

  - A logic issue was addressed with improved state management.

  - A buffer overflow was addressed with improved bounds checking.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  allow remote attackers to execute arbitrary code, bypass security restrictions,
  disclose sensitive information and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15 prior to 10.15.2,
  10.13.x prior to 10.13.6 Security Update 2019-007 and 10.14.x prior to 10.14.6
  Security Update 2019-002.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.15.2 or later
  or apply Security Update 2019-007 on 10.13.6 or apply Security Update 2019-002
  on 10.14.6.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210788");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[345]" || "Mac OS X" >!< osName)
  exit(0);

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.13") {
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6") {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G10021")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.14") {
  if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.14.6") {
    if(osVer == "10.14.6" && version_is_less(version:buildVer, test_version:"18G2022")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer =~ "^10\.15" && version_is_less(version:osVer, test_version:"10.15.2")) {
  fix = "10.15.2";
}

if(fix) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
