# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826953");
  script_version("2025-03-21T15:40:43+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-43551", "CVE-2022-43552", "CVE-2023-0049", "CVE-2023-0051",
                "CVE-2023-0054", "CVE-2023-0288", "CVE-2023-0433", "CVE-2023-0512",
                "CVE-2023-23514", "CVE-2023-23523", "CVE-2023-23525", "CVE-2023-23526",
                "CVE-2023-23527", "CVE-2023-23532", "CVE-2023-23533", "CVE-2023-23534",
                "CVE-2023-23535", "CVE-2023-23537", "CVE-2023-23538", "CVE-2023-23542",
                "CVE-2023-23543", "CVE-2023-27928", "CVE-2023-27929", "CVE-2023-27931",
                "CVE-2023-27932", "CVE-2023-27933", "CVE-2023-27934", "CVE-2023-27935",
                "CVE-2023-27936", "CVE-2023-27937", "CVE-2023-27941", "CVE-2023-27942",
                "CVE-2023-27943", "CVE-2023-27944", "CVE-2023-27946", "CVE-2023-27949",
                "CVE-2023-27951", "CVE-2023-27952", "CVE-2023-27953", "CVE-2023-27954",
                "CVE-2023-27955", "CVE-2023-27956", "CVE-2023-27957", "CVE-2023-27958",
                "CVE-2023-27961", "CVE-2023-27962", "CVE-2023-27963", "CVE-2023-27965",
                "CVE-2023-27968", "CVE-2023-27969", "CVE-2023-28178", "CVE-2023-28180",
                "CVE-2023-28181", "CVE-2023-28182", "CVE-2023-28190", "CVE-2023-28192",
                "CVE-2023-28200", "CVE-2023-23536", "CVE-2023-27939", "CVE-2023-27947",
                "CVE-2023-27948", "CVE-2023-27950", "CVE-2023-27966", "CVE-2023-28179",
                "CVE-2023-28187", "CVE-2023-28188", "CVE-2023-28189", "CVE-2023-28195",
                "CVE-2023-28198", "CVE-2023-28199", "CVE-2023-28201", "CVE-2023-28209",
                "CVE-2023-28210", "CVE-2023-28211", "CVE-2023-28212", "CVE-2023-28213",
                "CVE-2023-28214", "CVE-2023-28215", "CVE-2023-32356", "CVE-2023-32358",
                "CVE-2023-32362", "CVE-2023-32370", "CVE-2023-32426", "CVE-2023-32435",
                "CVE-2023-28197", "CVE-2023-32366", "CVE-2023-32378", "CVE-2023-32436",
                "CVE-2023-40383", "CVE-2023-40433", "CVE-2023-41075", "CVE-2023-42830",
                "CVE-2023-42862", "CVE-2023-42865", "CVE-2014-1745", "CVE-2023-40398",
                "CVE-2023-28207");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-21 15:40:43 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-15 13:24:00 +0000 (Mon, 15 May 2023)");
  script_tag(name:"creation_date", value:"2023-03-29 11:22:17 +0530 (Wed, 29 Mar 2023)");
  script_name("Apple Mac OS X Security Update (HT213670)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory handling issues.

  - Multiple validation issues.

  - Multiple issues in curl.

  - Improper checks and vulnerable code.

  - Improper state management.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, escalate privileges, bypass security
  restrictions and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Ventura prior to
  version 13.3.");

  script_tag(name:"solution", value:"Upgrade to version 13.3 for macOS Ventura 13.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213670");
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

if(version_is_less(version:osVer, test_version:"13.3")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
