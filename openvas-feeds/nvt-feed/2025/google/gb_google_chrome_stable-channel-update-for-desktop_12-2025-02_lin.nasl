# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834958");
  script_version("2025-04-09T05:39:51+0000");
  script_cve_id("CVE-2025-0995", "CVE-2025-0996", "CVE-2025-0997");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-13 10:43:11 +0530 (Thu, 13 Feb 2025)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_12-2025-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2025-0995: Use after free in V8

  - CVE-2025-0996: Inappropriate implementation in Browser UI

  - CVE-2025-0997: Use after free in Navigation

  Note: This advisory initially also contained CVE-2025-0998 but this CVE got rejected in the
  meantime.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, privilege escalation, disclose information and conduct
  denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  133.0.6943.98 on Linux");

  script_tag(name: "solution", value:"Update to version 133.0.6943.98 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_12.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"133.0.6943.98")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"133.0.6943.98", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
