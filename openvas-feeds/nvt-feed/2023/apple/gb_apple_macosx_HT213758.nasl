# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826991");
  script_version("2024-08-01T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-28204", "CVE-2023-32352", "CVE-2023-32355", "CVE-2023-32357",
                "CVE-2023-32360", "CVE-2023-32363", "CVE-2023-32367", "CVE-2023-32368",
                "CVE-2023-32369", "CVE-2023-32371", "CVE-2023-32372", "CVE-2023-32373",
                "CVE-2023-32375", "CVE-2023-32376", "CVE-2023-32380", "CVE-2023-32382",
                "CVE-2023-32384", "CVE-2023-32385", "CVE-2023-32386", "CVE-2023-32387",
                "CVE-2023-32388", "CVE-2023-32389", "CVE-2023-32390", "CVE-2023-32391",
                "CVE-2023-32392", "CVE-2023-32394", "CVE-2023-32395", "CVE-2023-32397",
                "CVE-2023-32398", "CVE-2023-32399", "CVE-2023-32400", "CVE-2023-32402",
                "CVE-2023-32403", "CVE-2023-32404", "CVE-2023-32405", "CVE-2023-32407",
                "CVE-2023-32408", "CVE-2023-32409", "CVE-2023-32410", "CVE-2023-32411",
                "CVE-2023-32412", "CVE-2023-32413", "CVE-2023-32414", "CVE-2023-32415",
                "CVE-2023-32420", "CVE-2023-32422", "CVE-2023-32423", "CVE-2023-34352",
                "CVE-2023-32379", "CVE-2023-32417", "CVE-2023-32428", "CVE-2023-32437",
                "CVE-2023-32432", "CVE-2023-22809", "CVE-2023-28202", "CVE-2023-27930",
                "CVE-2023-32383", "CVE-2023-32401", "CVE-2023-42869", "CVE-2023-29469",
                "CVE-2023-42958");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 07:04:00 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 11:55:29 +0530 (Mon, 22 May 2023)");
  script_name("Apple Mac OS X Security Update (HT213758)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper state and memory management.

  - Improper permissions checks and private data redaction.

  - Improper handling of temporary files.

  - Improper entitlements.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, bypass security restrictions and disclose
  sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.4.");

  script_tag(name:"solution", value:"Upgrade to version 13.4 for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213758");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.4")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
