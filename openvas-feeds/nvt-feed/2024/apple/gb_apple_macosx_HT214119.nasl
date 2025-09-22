# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834279");
  script_version("2025-05-16T05:40:21+0000");
  script_cve_id("CVE-2024-40804", "CVE-2023-38709", "CVE-2024-24795", "CVE-2024-27316",
                "CVE-2024-40783", "CVE-2024-40774", "CVE-2024-40814", "CVE-2024-40775",
                "CVE-2024-27877", "CVE-2024-27878", "CVE-2024-40799", "CVE-2024-27873",
                "CVE-2024-2004", "CVE-2024-2379", "CVE-2024-2398", "CVE-2024-2466",
                "CVE-2024-40827", "CVE-2024-40815", "CVE-2024-40795", "CVE-2023-6277",
                "CVE-2023-52356", "CVE-2024-40806", "CVE-2024-40777", "CVE-2024-40784",
                "CVE-2024-27863", "CVE-2024-40816", "CVE-2024-40788", "CVE-2024-40803",
                "CVE-2024-40805", "CVE-2024-40832", "CVE-2024-40796", "CVE-2024-6387",
                "CVE-2024-40781", "CVE-2024-40802", "CVE-2024-40823", "CVE-2024-27882",
                "CVE-2024-27883", "CVE-2024-40778", "CVE-2024-40800", "CVE-2023-27952",
                "CVE-2024-40817", "CVE-2024-40824", "CVE-2024-27871", "CVE-2024-27881",
                "CVE-2024-40821", "CVE-2024-40798", "CVE-2024-27872", "CVE-2024-27862",
                "CVE-2024-40833", "CVE-2024-40835", "CVE-2024-40836", "CVE-2024-40807",
                "CVE-2024-40834", "CVE-2024-40809", "CVE-2024-40812", "CVE-2024-40787",
                "CVE-2024-40793", "CVE-2024-40818", "CVE-2024-40822", "CVE-2024-40828",
                "CVE-2024-40811", "CVE-2024-40776", "CVE-2024-40782", "CVE-2024-40779",
                "CVE-2024-40780", "CVE-2024-40785", "CVE-2024-40789", "CVE-2024-4558",
                "CVE-2024-40794", "CVE-2024-40810", "CVE-2024-44141", "CVE-2024-44185",
                "CVE-2024-44205", "CVE-2024-44206", "CVE-2024-44306", "CVE-2024-44307",
                "CVE-2024-44199", "CVE-2024-44305", "CVE-2024-54551", "CVE-2024-54564");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 17:18:09 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-07-30 15:15:33 +0530 (Tue, 30 Jul 2024)");
  script_name("Apple MacOSX Security Update (HT214119, regreSSHion)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-40774: A downgrade issue was addressed with additional code-signing restrictions.

  - CVE-2024-27878: A buffer overflow issue was addressed with improved memory handling.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions,
  conduct spoofing and cause denial of service.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.6");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214119");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/120911");
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

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
