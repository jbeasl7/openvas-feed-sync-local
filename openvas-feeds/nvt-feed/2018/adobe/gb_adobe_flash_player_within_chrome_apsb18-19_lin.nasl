# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813400");
  script_version("2025-09-12T05:38:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-5002", "CVE-2018-4945", "CVE-2018-5000", "CVE-2018-5001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 15:36:30 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-06-08 12:21:40 +0530 (Fri, 08 Jun 2018)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (APSB18-19) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion error.

  - An integer overflow error.

  - An out-of-bounds read error.

  - A stack-based buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct arbitrary code execution and disclosure of sensitive
  information.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 30.0.0.113
  within Google Chrome on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for
  Google Chrome 30.0.0.113, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-19.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Lin/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"30.0.0.113")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"30.0.0.113", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
