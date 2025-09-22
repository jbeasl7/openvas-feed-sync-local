# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832896");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-2883", "CVE-2024-2885", "CVE-2024-2886", "CVE-2024-2887");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 16:04:04 +0000 (Thu, 19 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-27 09:58:37 +0530 (Wed, 27 Mar 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_26-2024-03) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-2883: Use after free in ANGLE

  - CVE-2024-2885: Use after free in Dawn

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code and potentially exploit heap corruption via a
  crafted HTML page.");

  script_tag(name:"affected", value:"Google Chrome prior to version
  123.0.6312.86 on Windows");

  script_tag(name:"solution", value:"Update to version 123.0.6312.86/.87 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/03/stable-channel-update-for-desktop_26.html");
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

if(version_is_less(version:vers, test_version:"123.0.6312.86")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"123.0.6312.86/.87", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
