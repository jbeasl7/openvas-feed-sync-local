# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832881");
  script_version("2024-04-26T15:38:47+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-23276", "CVE-2024-23227", "CVE-2024-23269", "CVE-2024-23247",
                "CVE-2024-23218", "CVE-2024-23244", "CVE-2024-23270", "CVE-2024-23286",
                "CVE-2024-23257", "CVE-2024-23234", "CVE-2024-23266", "CVE-2024-23265",
                "CVE-2024-23225", "CVE-2024-23201", "CVE-2023-28826", "CVE-2024-23264",
                "CVE-2024-23283", "CVE-2024-23274", "CVE-2024-23268", "CVE-2024-23275",
                "CVE-2024-23267", "CVE-2024-23216", "CVE-2024-23230", "CVE-2024-23204",
                "CVE-2024-23245", "CVE-2024-23272");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-26 15:38:47 +0000 (Fri, 26 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-14 20:34:18 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-22 16:19:56 +0530 (Fri, 22 Mar 2024)");
  script_name("Apple Mac OS X Security Update (HT214083)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-23216: A path handling issue

  - CVE-2024-23265: A memory corruption vulnerability

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution, information disclosure and denial of
  service.");

  script_tag(name:"affected", value:"Apple macOS Monterey prior to version
  12.7.4.");

  script_tag(name:"solution", value:"Update macOS Monterey to version 12.7.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214083");
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

if(version_is_less(version:osVer, test_version:"12.7.4")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.7.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
