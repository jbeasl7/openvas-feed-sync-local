# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836687");
  script_version("2025-09-26T05:38:41+0000");
  script_cve_id("CVE-2025-10890", "CVE-2025-10891", "CVE-2025-10892");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-25 15:55:41 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-24 17:58:22 +0530 (Wed, 24 Sep 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_23-2025-09) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to perform remote code execution, disclose information and conduct denial of service
  attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version 140.0.7339.207
  on Mac OS X");

  script_tag(name: "solution", value:"Update to version 140.0.7339.207/.208 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/09/stable-channel-update-for-desktop_23.html");
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

if(version_is_less(version:vers, test_version:"140.0.7339.207")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"140.0.7339.207/.208", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);