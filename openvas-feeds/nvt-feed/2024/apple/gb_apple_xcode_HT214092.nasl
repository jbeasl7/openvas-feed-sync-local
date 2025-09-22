# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832892");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-23298");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-09 14:44:22 +0000 (Mon, 09 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-26 05:48:09 +0530 (Tue, 26 Mar 2024)");
  script_name("Apple Xcode Security Update (HT214092)");

  script_tag(name:"summary", value:"Apple Xcode is prone to a gatekeeper bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  state management.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass Gatekeeper checks.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 15.3 on
  macOS Sonoma 14 and later.");

  script_tag(name:"solution", value:"Update to version 15.3 or later for macOS
  Sonoma.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214092");
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

if(version_is_less(version:vers, test_version:"15.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"15.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);

