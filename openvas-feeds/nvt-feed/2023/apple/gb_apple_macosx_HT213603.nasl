# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826795");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2022-32221", "CVE-2022-35260", "CVE-2022-3705", "CVE-2022-42915",
                "CVE-2022-42916", "CVE-2023-23493", "CVE-2023-23496", "CVE-2023-23497",
                "CVE-2023-23498", "CVE-2023-23499", "CVE-2023-23500", "CVE-2023-23501",
                "CVE-2023-23502", "CVE-2023-23503", "CVE-2023-23504", "CVE-2023-23505",
                "CVE-2023-23506", "CVE-2023-23507", "CVE-2023-23508", "CVE-2023-23510",
                "CVE-2023-23511", "CVE-2023-23512", "CVE-2023-23513", "CVE-2023-23517",
                "CVE-2023-23518", "CVE-2023-23519", "CVE-2023-23520", "CVE-2023-23530",
                "CVE-2023-23531");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-08 15:42:00 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 12:04:06 +0530 (Wed, 25 Jan 2023)");
  script_name("Apple Mac OS X Security Update (HT213603)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple issues in curl.

  - Runtime issue.

  - Multiple issues in state management.

  - Multiple memory handling issues.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  gain elevated privileges, execute arbitrary code with kernel privileges,
  disclose sensitive information and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.7.3.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.7.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213603");
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

if(version_is_less(version:osVer, test_version:"11.7.3"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.7.3");
  security_message(data:report);
  exit(0);
}
exit(99);
