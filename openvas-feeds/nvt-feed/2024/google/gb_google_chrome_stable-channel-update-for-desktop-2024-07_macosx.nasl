# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834261");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-6772", "CVE-2024-6773", "CVE-2024-6774", "CVE-2024-6775",
                "CVE-2024-6776", "CVE-2024-6777", "CVE-2024-6778", "CVE-2024-6779");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 15:41:39 +0000 (Thu, 26 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-07-17 10:28:17 +0530 (Wed, 17 Jul 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2024-07) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-6772: Inappropriate implementation in V8.

  - CVE-2024-6773: Type Confusion in V8.

  - CVE-2024-6774: Use after free in Screen Capture.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to run arbitrary code, disclose sensitive information, and cause
  denial of service.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  126.0.6478.182 on Mac OS X");

  script_tag(name: "solution", value:"Update to version 126.0.6478.182/183 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"126.0.6478.182")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"126.0.6478.182/183", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
