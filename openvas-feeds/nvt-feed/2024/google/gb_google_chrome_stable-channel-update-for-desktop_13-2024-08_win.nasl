# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834435");
  script_version("2024-08-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-23 10:14:48 +0530 (Fri, 23 Aug 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_13-2024-08) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to an unspecified
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unknown error.");

  script_tag(name: "impact" , value:"Successful exploitation may allow an attacker
  to have an impact on availability, integrity and confidentiality.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  127.0.6533.119 on Windows");

  script_tag(name: "solution", value:"Update to version 127.0.6533.119/.120 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_13.html");
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

if(version_is_less(version:vers, test_version:"127.0.6533.119")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127.0.6533.119/.120", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
