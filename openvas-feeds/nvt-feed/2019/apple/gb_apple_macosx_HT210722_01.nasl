# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815819");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8817", "CVE-2019-8788", "CVE-2019-8789", "CVE-2019-8858",
                "CVE-2019-8807", "CVE-2019-8754", "CVE-2017-7152", "CVE-2019-8805",
                "CVE-2019-8803", "CVE-2019-8801", "CVE-2019-8794", "CVE-2019-8829",
                "CVE-2019-15126", "CVE-2019-8784", "CVE-2019-8796");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-29 20:28:00 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-10-30 12:08:21 +0530 (Wed, 30 Oct 2019)");
  script_name("Apple Mac OS X Security Updates (HT210722)-01");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A validation issue related to improper input sanitization.

  - A memory corruption issue was addressed with improved memory handling.

  - An out-of-bounds read error related to improper input validation.

  - An issue existed in the parsing of URLs.

  - A validation issue related to handling of symlinks.

  - An inconsistent user interface issue related to improper state management.

  - Multiple memory corruption issues related to improper memory handling.

  - A dynamic library loading issue existed in iTunes setup.

  - A validation issue existed in the entitlement verification.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  read restricted memory, execute arbitrary code with system privileges, conduct
  data exfiltration, bypass authentication, disclosure of user information and
  conduct spoofing attack.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.15");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.15.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210722");
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
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer == "10.15")
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15.1");
  security_message(port:0, data:report);
  exit(0);
}
exit(0);
