# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836301");
  script_version("2025-05-14T05:40:11+0000");
  script_cve_id("CVE-2025-31246", "CVE-2025-31240", "CVE-2025-31237", "CVE-2025-31251",
                "CVE-2025-31235", "CVE-2025-31208", "CVE-2025-31196", "CVE-2025-31209",
                "CVE-2025-31239", "CVE-2025-31233", "CVE-2025-30453", "CVE-2025-24258",
                "CVE-2025-30448", "CVE-2025-31232", "CVE-2025-24144", "CVE-2025-31219",
                "CVE-2025-31241", "CVE-2024-8176", "CVE-2025-30440", "CVE-2025-31222",
                "CVE-2025-24274", "CVE-2025-24142", "CVE-2025-26465", "CVE-2025-26466",
                "CVE-2025-31245", "CVE-2025-31224", "CVE-2025-31221", "CVE-2025-31213",
                "CVE-2025-31247", "CVE-2025-30442", "CVE-2025-31242", "CVE-2025-31220",
                "CVE-2025-24155");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-14 09:15:14 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-05-13 22:03:43 +0530 (Tue, 13 May 2025)");
  script_name("Apple MacOSX Security Update (HT122717)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, elevate privileges, bypass
  security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.7.6");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.7.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/122717");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.7.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.7.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
