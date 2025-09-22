# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832055");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2023-2459", "CVE-2023-2460", "CVE-2023-2461", "CVE-2023-2462",
                "CVE-2023-2463", "CVE-2023-2464", "CVE-2023-2465", "CVE-2023-2466",
                "CVE-2023-2467", "CVE-2023-2468", "CVE-2023-7282");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-10 04:15:00 +0000 (Wed, 10 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-03 14:31:36 +0530 (Wed, 03 May 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2023-05) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Inappropriate implementation in Prompts.

  - Insufficient validation of untrusted input in Extensions.

  - Use after free in OS Inputs.

  - Inappropriate implementation in Full Screen Mode.

  - Inappropriate implementation in PictureInPicture.

  - Inappropriate implementation in CORS.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  113.0.5672.63 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  113.0.5672.63/.64 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"113.0.5672.63")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"113.0.5672.63", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
