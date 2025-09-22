# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832981");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2024-27805", "CVE-2024-27817", "CVE-2024-27831", "CVE-2024-27798",
                "CVE-2024-23229", "CVE-2024-27789", "CVE-2024-27799", "CVE-2024-27840",
                "CVE-2024-27810", "CVE-2024-27800", "CVE-2024-27802", "CVE-2024-27885",
                "CVE-2024-27824", "CVE-2024-27843", "CVE-2024-27806", "CVE-2024-27847",
                "CVE-2024-27796", "CVE-2024-27823", "CVE-2024-40771");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-14 13:43:48 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-05-14 15:02:42 +0530 (Tue, 14 May 2024)");
  script_name("Apple MacOSX Security Update (HT214105)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-23229: This issue was addressed with improved redaction of sensitive information

  - CVE-2024-27789: A logic issue was addressed with improved checks");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to obtain sensitive information.");

  script_tag(name:"affected", value:"Apple macOS Monterey prior to version
  12.7.5.");

  script_tag(name:"solution", value:"Update macOS Monterey to version 12.7.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214105");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName) {
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"12.7.5")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.7.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
