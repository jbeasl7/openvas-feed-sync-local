# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826466");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-3195", "CVE-2022-3196", "CVE-2022-3197", "CVE-2022-3198",
                "CVE-2022-3199", "CVE-2022-3200", "CVE-2022-3201");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 18:16:00 +0000 (Wed, 28 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-15 15:47:13 +0530 (Thu, 15 Sep 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_14-2022-09) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in Storage.

  - Use after free in PDF.

  - Use after free in Frames.

  - Heap buffer overflow in Internals.

  - Insufficient validation of untrusted input in DevTools.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, leak memory and cause a denial of service
  on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  105.0.5195.125 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  105.0.5195.125 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop_14.html");
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

if(version_is_less(version:vers, test_version:"105.0.5195.125")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"105.0.5195.125 or later", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
