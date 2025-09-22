# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812142");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2017-3112", "CVE-2017-3114", "CVE-2017-11213", "CVE-2017-11215",
                "CVE-2017-11225");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-09 17:47:00 +0000 (Tue, 09 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-11-15 13:50:31 +0530 (Wed, 15 Nov 2017)");
  script_name("Adobe Flash Player Security Update (APSB17-33) - Linux");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An Out-of-bounds Read vulnerability.

  - An Use after free vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  27.0.0.187.");

  script_tag(name:"solution", value:"Update to version 27.0.0.187 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-33.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"27.0.0.187")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"27.0.0.187", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
