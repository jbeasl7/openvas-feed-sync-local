# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834093");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2024-6100", "CVE-2024-6101", "CVE-2024-6102", "CVE-2024-6103");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-20 15:17:16 +0000 (Thu, 20 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-21 11:56:03 +0530 (Fri, 21 Jun 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_18-2024-06) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-6100: Type Confusion error in V8.

  - CVE-2024-6101: Inappropriate implementation in WebAssembly.

  - CVE-2024-6102: Out of bounds memory access in Dawn.

  - CVE-2024-6103: Use after free in Dawn.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, and cause denial of
  service.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  126.0.6478.114 on Windows");

  script_tag(name: "solution", value:"Update to version 126.0.6478.114/115 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/06/stable-channel-update-for-desktop_18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"126.0.6478.114")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"126.0.6478.114/115", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
