# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832336");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-35983", "CVE-2023-28319", "CVE-2023-28320", "CVE-2023-28321",
                "CVE-2023-28322", "CVE-2023-32416", "CVE-2023-36854", "CVE-2023-32418",
                "CVE-2023-32381", "CVE-2023-32433", "CVE-2023-35993", "CVE-2023-38606",
                "CVE-2023-32441", "CVE-2023-38565", "CVE-2023-38593", "CVE-2023-38421",
                "CVE-2023-38258", "CVE-2023-2953", "CVE-2023-38259", "CVE-2023-38602",
                "CVE-2023-32442", "CVE-2023-32443", "CVE-2023-41990", "CVE-2023-40442",
                "CVE-2023-40440", "CVE-2023-42829", "CVE-2023-42831", "CVE-2023-42832",
                "CVE-2023-1801", "CVE-2023-2426", "CVE-2023-2609", "CVE-2023-2610",
                "CVE-2023-1916", "CVE-2023-38603");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 18:16:00 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-25 15:52:56 +0530 (Tue, 25 Jul 2023)");
  script_name("Apple Mac OS X Security Updates (HT213844)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper usage and handling of curl, caches.

  - An improper entitlements.

  - An improper handling of temporary files.

  - An improper state and memory management, private data redaction for log entries.

  - An improper bounds checking and input validation.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  disclose sensitive information, escalate privileges and execute arbitrary code
  with kernel privileges on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.6.8.");

  script_tag(name:"solution", value:"Upgrade to version 12.6.8 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213844");
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
if(!osName) {
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"12.6.8")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.6.8");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
