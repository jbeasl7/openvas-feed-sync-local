# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826951");
  script_version("2025-01-22T05:38:11+0000");
  script_cve_id("CVE-2023-23540", "CVE-2022-26702", "CVE-2023-23527", "CVE-2023-27951",
                "CVE-2023-27961", "CVE-2023-23534", "CVE-2023-27955", "CVE-2023-27936",
                "CVE-2023-27935", "CVE-2023-27953", "CVE-2023-27958", "CVE-2023-23537",
                "CVE-2023-27937", "CVE-2023-27928", "CVE-2023-27946", "CVE-2023-23535",
                "CVE-2023-23514", "CVE-2023-28200", "CVE-2023-28182", "CVE-2023-27962",
                "CVE-2023-23542", "CVE-2023-28192", "CVE-2023-0433", "CVE-2023-0512",
                "CVE-2023-27944", "CVE-2023-28197", "CVE-2023-32366", "CVE-2023-32378",
                "CVE-2023-41075", "CVE-2023-28185", "CVE-2023-27941", "CVE-2023-28199",
                "CVE-2023-40398");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-12 18:47:00 +0000 (Fri, 12 May 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 11:22:17 +0530 (Wed, 29 Mar 2023)");
  script_name("Apple Mac OS X Security Update (HT213675)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free issues.

  - Multiple validation issues.

  - Multiple issues in Vim.

  - Multiple memory handling issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  gain elevated privileges, execute arbitrary code with kernel privileges,
  disclose sensitive information and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.7.5.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.7.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213675");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:osVer, test_version:"11.7.5"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.7.5");
  security_message(data:report);
  exit(0);
}
exit(99);
