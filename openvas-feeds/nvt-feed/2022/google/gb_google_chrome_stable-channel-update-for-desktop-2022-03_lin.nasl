# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820015");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-0789", "CVE-2022-0790", "CVE-2022-0791", "CVE-2022-0792",
                "CVE-2022-0793", "CVE-2022-0794", "CVE-2022-0795", "CVE-2022-0796",
                "CVE-2022-0797", "CVE-2022-0798", "CVE-2022-0799", "CVE-2022-0800",
                "CVE-2022-0801", "CVE-2022-0802", "CVE-2022-0803", "CVE-2022-0804",
                "CVE-2022-0805", "CVE-2022-0806", "CVE-2022-0807", "CVE-2022-0808",
                "CVE-2022-0809", "CVE-2022-4923", "CVE-2022-4922", "CVE-2022-4921");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 09:36:00 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-03 11:50:34 +0530 (Thu, 03 Mar 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2022-03) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Heap buffer overflow errors in ANGLE, Cast UI.

  - Use after free errors in Cast UI, Omnibox, Views, WebShare, Media, MediaStream,
    Browser Switcher, Accessibility and Chrome OS Shell.

  - Inappropriate implementation in Full screen mode, HTML parser, Permissions,
    Autofill, Blink and Omnibox.

  - Out of bounds memory access errors in WebXR, Mojo.

  - Out of bounds read in ANGLE.

  - Data leak in Canvas.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and leak sensitive information.");

  script_tag(name:"affected", value:"Google Chrome version prior to 99.0.4844.51
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 99.0.4844.51
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"99.0.4844.51")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"99.0.4844.51", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
