# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818128");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225",
                "CVE-2021-21226");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 15:22:00 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 12:44:14 +0530 (Mon, 17 May 2021)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_20-2021-04) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Use after free in navigation.

  - Heap buffer overflow in V8.

  - Integer overflow in Mojo.

  - Type Confusion in V8.

  - Out of bounds memory access in V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and gain access to sensitive
  data.");

  script_tag(name:"affected", value:"Google Chrome version prior to 90.0.4430.85 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 90.0.4430.85
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop_20.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"90.0.4430.85")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"90.0.4430.85", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
