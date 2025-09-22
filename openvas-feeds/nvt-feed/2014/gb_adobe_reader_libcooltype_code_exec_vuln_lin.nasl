# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804630");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2001-1069");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-05 12:35:17 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader libCoolType Library Code Execution Vulnerability - Linux");

  script_tag(name:"summary", value:"Adobe Reader is prone to a code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to the application creating 'AdobeFnt.lst' file with insecure
permissions.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to launch a symlink attack and
execute code on the system.");
  script_tag(name:"affected", value:"Adobe Reader version 4.0.5 and 5.0.5 on Linux.");
  script_tag(name:"solution", value:"Update to Adobe Reader version 5.0.6 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/7024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3225");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer  =~ "^(4|5)\.")
{
  if(version_is_equal(version:readerVer, test_version:"4.0.5")||
     version_is_equal(version:readerVer, test_version:"5.0.5"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
