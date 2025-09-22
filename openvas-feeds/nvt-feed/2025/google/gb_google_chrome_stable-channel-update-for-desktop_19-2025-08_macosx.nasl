# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836616");
  script_version("2025-08-22T05:39:46+0000");
  script_cve_id("CVE-2025-9132");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-21 12:01:05 +0530 (Thu, 21 Aug 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_19-2025-08) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to an out of bounds write
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to potentially exploit heap corruption via a crafted HTML page.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  139.0.7258.138 on Mac OS X");

  script_tag(name: "solution", value:"Update to version 139.0.7258.138/.139 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/08/stable-channel-update-for-desktop_19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"139.0.7258.138")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"139.0.7258.138/.139", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
