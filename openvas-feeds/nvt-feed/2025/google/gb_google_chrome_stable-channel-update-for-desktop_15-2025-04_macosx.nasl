# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836142");
  script_version("2025-04-17T05:39:39+0000");
  script_cve_id("CVE-2025-3619", "CVE-2025-3620");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-04-17 05:39:39 +0000 (Thu, 17 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-16 09:51:39 +0530 (Wed, 16 Apr 2025)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_15-2025-04) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2025-3619: Heap buffer overflow in Codecs.

  - CVE-2025-3620: Use after free in USB.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute malicious code and gain unauthorized access to the system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  135.0.7049.95 on Mac OS X");

  script_tag(name:"solution", value:"Update to version 135.0.7049.95/.96 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2025/04/stable-channel-update-for-desktop_15.html");
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

if(version_is_less(version:vers, test_version:"135.0.7049.95")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"135.0.7049.95/.96", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
