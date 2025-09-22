# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811874");
  script_version("2023-11-08T05:05:52+0000");
  script_cve_id("CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127",
                "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5132", "CVE-2017-5130",
                "CVE-2017-5131", "CVE-2017-5133", "CVE-2017-15386", "CVE-2017-15387",
                "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391",
                "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395",
                "CVE-2017-15401");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-08 05:05:52 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-23 15:55:00 +0000 (Fri, 23 Feb 2018)");
  script_tag(name:"creation_date", value:"2017-10-19 12:40:22 +0530 (Thu, 19 Oct 2017)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2017-10) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An input validation error in MHTML.

  - Multiple heap overflow errors in Skia, WebGL and libxml2.

  - Multiple use after free errors in PDFium and WebAudio.

  - An incorrect stack manipulation in WebAssembly.

  - Multiple Out of bounds read and write errors in Skia.

  - UI spoofing in Blink.

  - Content security bypass.

  - Multiple URL spoofing errors in OmniBox.

  - An extension limitation bypass in Extensions.

  - An incorrect registry key handling in PlatformIntegration.

  - A memory corruption bug in WebAssembly.

  - Referrer leak in Devtools.

  - URL spoofing in extensions UI.

  - Null pointer dereference error in ImageCapture.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary script,
  conduct spoofing attack, corrupt memory, bypass security and cause
  denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  62.0.3202.62 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  62.0.3202.62 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101482");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"62.0.3202.62"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"62.0.3202.62");
  security_message(data:report);
  exit(0);
}
