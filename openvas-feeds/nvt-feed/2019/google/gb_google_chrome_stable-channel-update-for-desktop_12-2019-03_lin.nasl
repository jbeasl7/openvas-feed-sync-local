# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814868");
  script_version("2024-12-12T09:30:20+0000");
  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790",
                "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794",
                "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798",
                "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802",
                "CVE-2019-5803", "CVE-2019-5804", "CVE-2018-20072");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-11 14:26:00 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-03-14 12:14:20 +0530 (Thu, 14 Mar 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_12-2019-03) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use after free errors in Canvas, FileAPI, WebMIDI.

  - Heap buffer overflow error in V8.

  - Type confusion error in V8.

  - Integer overflow error in PDFium.

  - Excessive permissions for private API in Extensions.

  - Security UI spoofing.

  - Race condition in Extensions and DOMStorage.

  - Out of bounds read error in Skia.

  - CSP bypass errors with blob URL and Javascript URLs'.

  - Incorrect Omnibox display on iOS.

  - Command line command injection on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary code, cause denial of service and spoofing attacks,
  and also take control of an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 73.0.3683.75 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 73.0.3683.75 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/03/stable-channel-update-for-desktop_12.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"73.0.3683.75"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"73.0.3683.75", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
