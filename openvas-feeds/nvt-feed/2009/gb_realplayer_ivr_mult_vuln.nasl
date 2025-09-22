# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800509");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0375", "CVE-2009-0376");
  script_name("RealPlayer IVR Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/367866.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33652");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/367867.php");
  script_xref(name:"URL", value:"http://www.fortiguardcenter.com/advisory/FGA-2009-04.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/500722/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application and can cause heap overflow
  or cause remote code execution to the application.");
  script_tag(name:"affected", value:"RealPlayer 11.0.0.477 and prior on all Windows platforms.");
  script_tag(name:"insight", value:"- Memory corruption while the application processes crafted arbitrary
    'IVR' file.

  - A vulnerability that allows an attacker to write one null byte to an
    arbitrary memory address by using an overly long file name length value.");
  script_tag(name:"solution", value:"Upgrage to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"RealPlayer is prone to IVR multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(rpVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:rpVer, test_version:"11.0.0.477")){
  report = report_fixed_ver(installed_version:rpVer, vulnerable_range:"Less than or equal to 11.0.0.477");
  security_message(port: 0, data: report);
}
