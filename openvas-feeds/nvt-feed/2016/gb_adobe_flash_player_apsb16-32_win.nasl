# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809441");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2016-4273", "CVE-2016-4286", "CVE-2016-6981", "CVE-2016-6982",
                "CVE-2016-6983", "CVE-2016-6984", "CVE-2016-6985", "CVE-2016-6986",
                "CVE-2016-6987", "CVE-2016-6989", "CVE-2016-6990", "CVE-2016-6992");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 16:37:00 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"creation_date", value:"2016-10-12 19:02:24 +0530 (Wed, 12 Oct 2016)");
  script_name("Adobe Flash Player Security Update (APSB16-32) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion vulnerability.

  - The use-after-free vulnerabilities.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers lead to code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.382 and 22.x before 23.0.0.185.");

  script_tag(name:"solution", value:"Update to version 18.0.0.382, 23.0.0.185 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-32.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93490");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93497");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93492");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"22", test_version2:"23.0.0.184")) {
  fix = "23.0.0.185";
  VULN = TRUE;
}

else if(version_is_less(version:vers, test_version:"18.0.0.382")) {
  fix = "18.0.0.382";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
