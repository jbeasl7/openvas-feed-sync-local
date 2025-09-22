# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834431");
  script_version("2025-01-13T08:32:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-7964", "CVE-2024-7965", "CVE-2024-7966", "CVE-2024-7967",
                "CVE-2024-7968", "CVE-2024-7969", "CVE-2024-7971", "CVE-2024-7972",
                "CVE-2024-7973", "CVE-2024-7974", "CVE-2024-7975", "CVE-2024-7976",
                "CVE-2024-7977", "CVE-2024-7978", "CVE-2024-7979", "CVE-2024-7980",
                "CVE-2024-7981", "CVE-2024-8033", "CVE-2024-8034", "CVE-2024-8035");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 17:21:35 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-08-22 10:57:59 +0530 (Thu, 22 Aug 2024)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_21-2024-08) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7964: Use after free error in Passwords.

  - CVE-2024-7965: Inappropriate implementation in V8.

  - CVE-2024-7974: Insufficient data validation in V8 API.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to perform privilege escalation, run arbitrary code, conduct spoofing and
  cause denial of service attacks.");

  script_tag(name: "affected" , value:"Google Chrome prior to version
  128.0.6613.84 on Mac OS X");

  script_tag(name: "solution", value:"Update to version 128.0.6613.84/.85 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2024/08/stable-channel-update-for-desktop_21.html");
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

if(version_is_less(version:vers, test_version:"128.0.6613.84")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.0.6613.84/.85", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
