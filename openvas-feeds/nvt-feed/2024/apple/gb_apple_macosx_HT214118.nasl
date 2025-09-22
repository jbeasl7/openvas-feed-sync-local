# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834278");
  script_version("2025-05-16T05:40:21+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-40783", "CVE-2024-27826", "CVE-2024-40775", "CVE-2024-40774",
                "CVE-2024-27877", "CVE-2024-40799", "CVE-2024-27873", "CVE-2024-2004",
                "CVE-2024-2379", "CVE-2024-2398", "CVE-2024-2466", "CVE-2024-40827",
                "CVE-2024-40828", "CVE-2023-6277", "CVE-2023-52356", "CVE-2024-40806",
                "CVE-2024-40816", "CVE-2024-40788", "CVE-2024-40803", "CVE-2024-40796",
                "CVE-2024-6387", "CVE-2024-40781", "CVE-2024-40802", "CVE-2024-40823",
                "CVE-2024-27882", "CVE-2024-27883", "CVE-2024-40800", "CVE-2024-23296",
                "CVE-2024-40817", "CVE-2024-27881", "CVE-2024-40821", "CVE-2024-40798",
                "CVE-2024-40833", "CVE-2024-40835", "CVE-2024-40807", "CVE-2024-40834",
                "CVE-2024-40787", "CVE-2024-40793", "CVE-2024-40809", "CVE-2024-40812",
                "CVE-2024-23261", "CVE-2024-44205");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-05 15:10:37 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-30 15:15:33 +0530 (Tue, 30 Jul 2024)");
  script_name("Apple MacOSX Security Update (HT214118, regreSSHion)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-40774: A downgrade issue was addressed with additional code-signing restrictions.

  - CVE-2024-40799: An out-of-bounds read issue was addressed with improved input validation.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions,
  conduct spoofing and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Monterey prior to version
  12.7.6.");

  script_tag(name:"solution", value:"Update macOS Monterey to version 12.7.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214118");
  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-9.8");
  script_xref(name:"URL", value:"https://www.openssh.com/security.html");
  script_xref(name:"URL", value:"https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt");
  script_xref(name:"URL", value:"https://www.qualys.com/regresshion-cve-2024-6387/");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server");
  script_xref(name:"URL", value:"https://unit42.paloaltonetworks.com/threat-brief-cve-2024-6387-openssh/");
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

if(version_is_less(version:osVer, test_version:"12.7.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.7.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
