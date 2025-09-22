# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836172");
  script_version("2025-05-01T05:40:03+0000");
  script_cve_id("CVE-2025-4096", "CVE-2025-4050", "CVE-2025-4051", "CVE-2025-4052");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-30 10:14:20 +0530 (Wed, 30 Apr 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_29-2025-04) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and conduct denial of service
  attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  136.0.7103.48 on Windows");

  script_tag(name: "solution", value:"Update to version 136.0.7103.48/49 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/04/stable-channel-update-for-desktop_29.html");
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

if(version_is_less(version:vers, test_version:"136.0.7103.48")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"136.0.7103.48/49", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
