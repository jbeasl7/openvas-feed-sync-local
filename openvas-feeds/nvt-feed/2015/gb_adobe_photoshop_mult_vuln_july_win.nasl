# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805597");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-3112", "CVE-2015-3111", "CVE-2015-3110", "CVE-2015-3109");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-02 10:41:14 +0530 (Thu, 02 Jul 2015)");
  script_name("Adobe Photoshop CC Multiple Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an integer
  overflow error, multiple memory corruption errors and a heap based overflow
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial-of-service attacks and take complete control of the
  affected system.");

  script_tag(name:"affected", value:"Adobe Photoshop CC before version 16.0
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC version
  16.0 (2015.0.0) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb15-12.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75242");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/ProdVer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

prodVer = get_kb_item("Adobe/Photoshop/ProdVer");
if(!prodVer){
  exit(0);
}

if(version_is_less(version:prodVer, test_version:"16.0"))
{
  report = 'Installed version: ' + prodVer + '\n' +
           'Fixed version:     16.0'  + '\n';
  security_message(data:report);
  exit(0);
}
