# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836097");
  script_version("2025-04-04T05:39:39+0000");
  script_cve_id("CVE-2025-24226", "CVE-2025-30441");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-04 05:39:39 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-03 10:29:40 +0530 (Thu, 03 Apr 2025)");
  script_name("Apple Xcode Security Update (HT122380)");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to overwrite arbitrary files and access private information.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 16.3 on
  macOS Sequoia.");

  script_tag(name:"solution", value:"Update to version 16.3 or later for macOS
  Sequoia.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/122380");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^15\.") {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit(0);
}

vers = infos["version"];
path = infos["location"];

if(osVer =~ "^15\." && version_is_greater_equal(version:osVer, test_version:"15.2")) {
  if(version_is_less(version:vers, test_version:"16.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.3", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(0);