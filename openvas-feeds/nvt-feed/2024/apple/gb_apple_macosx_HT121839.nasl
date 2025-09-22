# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834555");
  script_version("2025-09-03T05:38:18+0000");
  script_cve_id("CVE-2023-32395", "CVE-2024-44220", "CVE-2024-44224", "CVE-2024-44225",
                "CVE-2024-44243", "CVE-2024-44245", "CVE-2024-44246", "CVE-2024-44291",
                "CVE-2024-44300", "CVE-2024-45490", "CVE-2024-54465", "CVE-2024-54466",
                "CVE-2024-54474", "CVE-2024-54476", "CVE-2024-54477", "CVE-2024-54479",
                "CVE-2024-54484", "CVE-2024-54486", "CVE-2024-54489", "CVE-2024-54490",
                "CVE-2024-54491", "CVE-2024-54492", "CVE-2024-54493", "CVE-2024-54494",
                "CVE-2024-54495", "CVE-2024-54498", "CVE-2024-54500", "CVE-2024-54501",
                "CVE-2024-54502", "CVE-2024-54504", "CVE-2024-54505", "CVE-2024-54506",
                "CVE-2024-54508", "CVE-2024-54510", "CVE-2024-54513", "CVE-2024-54514",
                "CVE-2024-54515", "CVE-2024-54524", "CVE-2024-54526", "CVE-2024-54527",
                "CVE-2024-54528", "CVE-2024-54529", "CVE-2024-54531", "CVE-2024-54534",
                "CVE-2024-54525", "CVE-2024-54559", "CVE-2024-54565", "CVE-2024-44271",
                "CVE-2024-54568");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-13 17:42:04 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-12 10:55:28 +0530 (Thu, 12 Dec 2024)");
  script_name("Apple MacOSX Security Update (HT121839)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, elevate privileges, and cause
  denial of service.");

  script_tag(name:"affected", value:"Apple macOS Sequoia prior to version
  15.2.");

  script_tag(name:"solution", value:"Update macOS Sequoia to version 15.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121839");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^15\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^15\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"15.2")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"15.2");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
