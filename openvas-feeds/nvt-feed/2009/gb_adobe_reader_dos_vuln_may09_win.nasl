# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800706");
  script_version("2024-02-21T05:06:26+0000");
  script_cve_id("CVE-2009-1492");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:26 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_name("Adobe Reader/Acrobat Denial of Service Vulnerability (May 2009)");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw is due to memory corruption error in 'getAnnots' methods in the
  JavaScript API while processing malicious PDF files that calls this vulnerable
  method with crafted integer arguments.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory corruption or
  denial of service.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.1 and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.3.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34924");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34736");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50145");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/04/update_on_adobe_reader_issue.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"9.1")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 9.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
