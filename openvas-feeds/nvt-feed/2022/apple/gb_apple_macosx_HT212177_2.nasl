# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826549");
  script_version("2025-07-17T05:43:33+0000");
  script_cve_id("CVE-2021-3156");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 23:16:40 +0530 (Thu, 22 Sep 2022)");
  script_name("Apple Mac OS X Security Update (HT212177, Baron Samedit)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone is prone to a heap-based buffer overflow
  vulnerability in sudo dubbed 'Baron Samedit'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to vulnerable sudo version.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to elevate their privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur 11.2, macOS Catalina 10.15.x
  prior to macOS Catalina 10.15.7 Supplemental Update, macOS Mojave 10.14.x
  prior to macOS Mojave 10.14.6 Security Update 2021-002.");

  script_tag(name:"solution", value:"Upgrade to version 11.2.1 or apply
  macOS Catalina 10.15.7 Supplemental Update for 10.15.x or apply Security Update 2021-002
  for macOS Mojave 10.14.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212177");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/stable/#1.9.5p2");
  script_xref(name:"URL", value:"https://www.sudo.ws/releases/legacy/#1.8.32");
  script_xref(name:"URL", value:"https://www.sudo.ws/security/advisories/unescape_overflow/");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.15");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName) {
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer == "11.2") {
  fix = "11.2.1";
}

else if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.6")) {
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.15.7") {
  if(version_is_less(version:buildVer, test_version:"19H524")) {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

else if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")) {
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.14.6") {
  if(version_is_less(version:buildVer, test_version:"18G8022")) {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
