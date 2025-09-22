# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834616");
  script_version("2024-11-01T05:05:36+0000");
  script_cve_id("CVE-2024-44162", "CVE-2024-40862", "CVE-2024-44191", "CVE-2024-32002",
                "CVE-2024-44228");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 20:40:28 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2024-09-19 12:14:24 +0530 (Thu, 19 Sep 2024)");
  script_name("Apple Xcode Security Update (HT121239)");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-44162: This issue was addressed by enabling hardened runtime

  - CVE-2024-40862: A privacy issue was addressed by removing sensitive data

  - CVE-2024-44191: This issue was addressed through improved state management");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to gain unauthorized access and execute remote code.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 16 on
  macOS Sonoma.");

  script_tag(name:"solution", value:"Update to version 16 or later for macOS
  Sonoma.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121239");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\.") {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit(0);
}

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);

