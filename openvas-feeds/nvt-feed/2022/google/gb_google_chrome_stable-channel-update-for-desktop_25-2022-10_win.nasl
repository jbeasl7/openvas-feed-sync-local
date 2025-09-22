# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826607");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-3652", "CVE-2022-3653", "CVE-2022-3654", "CVE-2022-3655",
                "CVE-2022-3656", "CVE-2022-3657", "CVE-2022-3658", "CVE-2022-3659",
                "CVE-2022-3660", "CVE-2022-3661", "CVE-2022-4910", "CVE-2022-4909",
                "CVE-2022-4908");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-02 19:19:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-28 13:36:58 +0530 (Fri, 28 Oct 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_25-2022-10) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Type Confusion in V8.

  - Heap buffer overflow in Vulkan.

  - Use after free in Layout.

  - Heap buffer overflow in Media Galleries.

  - Insufficient data validation in File System.

  - Use after free in Extensions.

  - Use after free in Feedback service on Chrome OS.

  - Use after free in Accessibility.

  - Inappropriate implementation in Full screen mode.

  - Insufficient data validation in Extensions.

  - Inappropriate implementation in iFrame Sandbox.

  - Inappropriate implementation in Autofill.

  - Inappropriate implementation in XML.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and corrupt memory on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  107.0.5304.62 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  107.0.5304.62 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"107.0.5304.62")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"107.0.5304.62", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
