# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813885");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16065",
                "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16085",
                "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076",
                "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080",
                "CVE-2018-16081", "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084",
                "CVE-2018-16072", "CVE-2018-16087", "CVE-2018-16088", "CVE-2018-17457",
                "CVE-2018-16086");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-15 14:35:00 +0000 (Tue, 15 Jan 2019)");
  script_tag(name:"creation_date", value:"2018-09-05 11:42:16 +0530 (Wed, 05 Sep 2018)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2018-09) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple out of bounds write errors in V8 and Mojo.

  - A missing check for JS-simulated input events in Blink.

  - A missing origin check related to HLS manifests in Blink.

  - Multiple out of bounds read errors in Blink, WebAudio, SwiftShader, Little-CMS,
    PDFium and WebRTC.

  - An integer overflow error in Skia.

  - Multiple use after free errors in WebRTC and Memory Instrumentation.

  - An user confirmation bypass error in external protocol handling.

  - A stack buffer overflow error in SwiftShader.

  - An improper file access control in DevTools and Blink.

  - Multiple url spoofing errors.

  - The content security policy bypass error in Blink.

  - A security bypass error in Autofill.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions, cause denial of service condition,
  disclose sensitive information and conduct spoofing attack.");

  script_tag(name:"affected", value:"Google Chrome version prior to  69.0.3497.81
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 69.0.3497.81
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/09/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos["version"];
chr_path = infos["location"];

if(version_is_less(version:chr_ver, test_version:"69.0.3497.81"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"69.0.3497.81", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(0);
