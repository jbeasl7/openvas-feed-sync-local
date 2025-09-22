# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814873");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2019-7094");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-03-18 16:31:23 +0530 (Mon, 18 Mar 2019)");
  script_name("Adobe Photoshop CC Arbitrary Code Execution Vulnerability (APSB19-15) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a heap corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application. Failed
  attempts may lead to denial-of-service conditions.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2018 19.1.7 and earlier
  and Adobe Photoshop CC 2019 20.0.2 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2018 19.1.8
  or Photoshop CC 2019 20.0.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-15.html");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:photoshop_cc2018", "cpe:/a:adobe:photoshop_cc2019");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^19\.") {
  if(version_is_less_equal(version:vers, test_version:"19.1.8")) {
    fix = "19.1.8";
    installed_ver = "Adobe Photoshop CC 2018";
  }
}

else if(vers =~ "^20\.") {
  if(version_is_less_equal(version:vers, test_version:"20.0.4")) {
    fix = "20.0.4";
    installed_ver = "Adobe Photoshop CC 2019";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
