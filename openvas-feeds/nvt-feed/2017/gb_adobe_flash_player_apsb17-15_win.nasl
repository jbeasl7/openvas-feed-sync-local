# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811101");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2017-3068", "CVE-2017-3069", "CVE-2017-3070", "CVE-2017-3071",
                "CVE-2017-3072", "CVE-2017-3073", "CVE-2017-3074");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 18:12:00 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-05-10 07:59:40 +0530 (Wed, 10 May 2017)");
  script_name("Adobe Flash Player Security Update (APSB17-15) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A use-after-free vulnerability and

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute the code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  25.0.0.171.");

  script_tag(name:"solution", value:"Update to version 25.0.0.171 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-15.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98347");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"25.0.0.171")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"25.0.0.171", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
