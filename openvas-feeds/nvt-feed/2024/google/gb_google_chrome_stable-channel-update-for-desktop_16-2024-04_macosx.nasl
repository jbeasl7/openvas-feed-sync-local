# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832942");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2024-3832", "CVE-2024-3833", "CVE-2024-3914", "CVE-2024-3834",
                "CVE-2024-3837", "CVE-2024-3838", "CVE-2024-3839", "CVE-2024-3840",
                "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845",
                "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-7019", "CVE-2024-7020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-19 17:20:22 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-17 17:26:13 +0530 (Wed, 17 Apr 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_16-2024-04) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-3832: Object corruption in V8.

  - CVE-2024-3833: Object corruption in WebAssembly.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, conduct spoofing and
  cause a denial of service.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  124.0.6367.60 on Mac OS X");

  script_tag(name:"solution", value:"Update to version 124.0.6367.60/.61 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/04/stable-channel-update-for-desktop_16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"124.0.6367.60")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"124.0.6367.60/.61", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
