# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:lightroom_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826486");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2021-40776");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 21:15:00 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-09-27 21:02:01 +0530 (Tue, 27 Sep 2022)");
  script_name("Adobe Lightroom Classic Privilege escalation Vulnerability (APSB21-97) - Windows");

  script_tag(name:"summary", value:"Adobe Lightroom Classic is privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Creation of Temporary
  File in Directory with Incorrect Permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges on victim's system.");

  script_tag(name:"affected", value:"Adobe Lightroom Classic 10.3 and earlier
  versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Lightroom Classic 10.4 or
  11.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/lightroom/apsb21-97.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_lightroom_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Lightroom/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"10.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.4 or 11.0 or later", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
