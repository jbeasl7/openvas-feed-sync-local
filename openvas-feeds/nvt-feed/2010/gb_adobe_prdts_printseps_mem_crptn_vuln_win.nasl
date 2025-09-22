# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801545");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-4091");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Acrobat and Reader 'printSeps()' Function Heap Corruption Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44638");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62996");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15419/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2890");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2010/11/potential-issue-in-adobe-reader.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to crash an affected application
  or compromise a vulnerable system by tricking a user into opening a specially crafted PDF file.");

  script_tag(name:"affected", value:"Adobe Reader version 8.x to 8.1.7 and 9.x before 9.4.1

  Adobe Acrobat version 8.x to 8.1.7 and 9.x before 9.4.1 on Windows.");

  script_tag(name:"insight", value:"This issue is caused by a heap corruption error in the 'EScript.api' plugin
  when processing the 'printSeps()' function within a PDF document.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.4.1 or later.");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to heap corruption Vulnerability");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"8.1.7") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.4.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.4.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
