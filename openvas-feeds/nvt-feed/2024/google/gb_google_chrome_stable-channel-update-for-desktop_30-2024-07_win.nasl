# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834284");
  script_version("2024-08-19T05:05:38+0000");
  script_cve_id("CVE-2024-6990", "CVE-2024-7255", "CVE-2024-7256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-19 05:05:38 +0000 (Mon, 19 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-16 15:23:19 +0000 (Fri, 16 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-31 21:28:05 +0530 (Wed, 31 Jul 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_30-2024-07) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-6990: Uninitialized Use in Dawn.

  - CVE-2024-7255: Out of bounds read error in WebTransport.

  - CVE-2024-7256: Insufficient data validation error in Dawn.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and elevate privileges.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  127.0.6533.88 on Windows");

  script_tag(name: "solution", value:"Update to version 127.0.6533.88/89 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/07/stable-channel-update-for-desktop_30.html");
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

if(version_is_less(version:vers, test_version:"127.0.6533.88")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127.0.6533.88/89", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
