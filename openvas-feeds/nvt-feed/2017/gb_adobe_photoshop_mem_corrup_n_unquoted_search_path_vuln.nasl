# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811017");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-3004", "CVE-2017-3005");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 13:55:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-05-03 14:33:41 +0530 (Wed, 03 May 2017)");
  script_name("Adobe Photoshop Memory Corruption and Unquoted Search Path Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to memory corruption and unquoted search path vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to a memory
  corruption error when parsing malicious PCX files and an unquoted search path
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application and gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 before 18.1
  and Adobe Photoshop CC 2015.5 before 17.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017 18.1
  or Adobe Photoshop CC 2015.5 17.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb17-12.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97559");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97553");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:photoshop_cc2017",
                     "cpe:/a:adobe:photoshop_cc2015.5");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:photoshop_cc2017" ) {
  if(version_is_less(version:vers, test_version:"18.1")) {
    fix = "CC 2017 18.1";
    VULN = TRUE;
    prodVer = "CC 2017 " + vers;
  }
} else if(cpe == "cpe:/a:adobe:photoshop_cc2015.5" ) {
  if(version_is_less(version:vers, test_version:"17.0.2")) {
    fix = "CC 2015.5 17.0.2 (2015.5.2)";
    VULN = TRUE;
    prodVer = "CC 2015.5 " + vers;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:prodVer, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
