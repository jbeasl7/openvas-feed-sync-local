# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815874");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8853", "CVE-2019-8856", "CVE-2019-8834", "CVE-2020-9782");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-04 00:55:00 +0000 (Wed, 04 Nov 2020)");
  script_tag(name:"creation_date", value:"2019-12-12 11:00:05 +0530 (Thu, 12 Dec 2019)");
  script_name("Apple Mac OS X Security Updates (HT210788)-01");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A validation issue was addressed with improved input sanitization.

  - An API issue existed in the handling of outgoing phone calls initiated with Siri.

  - A configuration issue was addressed with additional restrictions.

  - A parsing issue in the handling of directory paths was addressed with improved path validation.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  read restricted memory, execute arbitrary code, conduct denial of service
  attack and disclosure of user information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15.x prior to 10.15.2.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.15.2 or later.");

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
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName)
  exit(0);

if(version_is_less(version:osVer, test_version:"10.15.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
