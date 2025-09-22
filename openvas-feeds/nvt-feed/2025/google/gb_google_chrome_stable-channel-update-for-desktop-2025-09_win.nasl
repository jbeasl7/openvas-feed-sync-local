# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836631");
  script_version("2025-09-05T05:38:20+0000");
  script_cve_id("CVE-2025-9864", "CVE-2025-9865", "CVE-2025-9866", "CVE-2025-9867");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-05 05:38:20 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-03 16:00:21 +0530 (Wed, 03 Sep 2025)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop-2025-09) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to execute arbitrary code and cause system crashes.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  140.0.7339.80 on Windows");

  script_tag(name: "solution", value:"Update to version 140.0.7339.80/81 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/09/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"140.0.7339.80")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"140.0.7339.80/81", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
