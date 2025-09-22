# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820091");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-1477", "CVE-2022-1478", "CVE-2022-1479", "CVE-2022-1480",
                "CVE-2022-1481", "CVE-2022-1482", "CVE-2022-1483", "CVE-2022-1484",
                "CVE-2022-1485", "CVE-2022-1486", "CVE-2022-1487", "CVE-2022-1488",
                "CVE-2022-1489", "CVE-2022-1490", "CVE-2022-1491", "CVE-2022-1492",
                "CVE-2022-1493", "CVE-2022-1494", "CVE-2022-1495", "CVE-2022-1496",
                "CVE-2022-1497", "CVE-2022-1498", "CVE-2022-1499", "CVE-2022-1500",
                "CVE-2022-1501", "CVE-2022-4920", "CVE-2022-4919");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 16:39:00 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2022-04-29 12:15:54 +0530 (Fri, 29 Apr 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_26-2022-04) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Multiple heap buffer overflow errors.

  - Type Confusion error in V8.

  - Multiple data validation errors.

  - Multiple implementation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct privilege escalation, bypass security restrictions, execute arbitrary
  code and cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to 101.0.4951.41
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 101.0.4951.41
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_26.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"101.0.4951.41")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"101.0.4951.41", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
