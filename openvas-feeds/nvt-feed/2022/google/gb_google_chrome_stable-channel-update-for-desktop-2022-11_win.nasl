# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826707");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-3885", "CVE-2022-3886", "CVE-2022-3887", "CVE-2022-3888",
                "CVE-2022-3889", "CVE-2022-3890");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 22:15:00 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-18 15:33:31 +0530 (Fri, 18 Nov 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2022-11) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in V8.

  - Use after free in Speech Recognition.

  - Use after free in Web Workers.

  - Use after free in WebCodecs.

  - Type Confusion in V8.

  - Heap buffer overflow in Crashpad.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  107.0.5304.106/.107 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  107.0.5304.106/.107 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"107.0.5304.106")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"107.0.5304.106", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
