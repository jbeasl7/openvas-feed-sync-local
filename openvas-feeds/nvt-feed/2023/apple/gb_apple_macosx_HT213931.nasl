# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832289");
  script_version("2025-04-16T05:39:43+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-40412", "CVE-2023-40409", "CVE-2023-41071", "CVE-2023-40410",
                "CVE-2023-41232", "CVE-2023-40406", "CVE-2023-40420", "CVE-2023-41984",
                "CVE-2023-41981", "CVE-2023-41992", "CVE-2023-41073", "CVE-2023-40454",
                "CVE-2023-40403", "CVE-2023-40427", "CVE-2023-41063", "CVE-2023-40452",
                "CVE-2023-41996", "CVE-2023-41991", "CVE-2023-41070", "CVE-2023-41968",
                "CVE-2023-38612", "CVE-2023-42961", "CVE-2023-42969");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 16:43:00 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-04 13:23:19 +0530 (Wed, 04 Oct 2023)");
  script_name("Apple Mac OS X Security Update (HT213931)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper checks.

  - Improper state management.

  - Improper validation of symlinks, signature.

  - An improper input validation.

  - An improper memory handling.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, privilege escalation, information disclosure.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version 13.6.");

  script_tag(name:"solution", value:"Upgrade to version 13.6 for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213931");
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

if(version_is_less(version:osVer, test_version:"13.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
