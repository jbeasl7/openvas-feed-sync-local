# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901096");
  script_version("2024-07-01T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-4324");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:20:36 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_name("Adobe Reader/Acrobat Multimedia Doc.media.newPlayer Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to Doc.media.newPlayer Remote Code Execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exists a flaw in the JavaScript module doc.media object while sending a
  null argument to the newPlayer() method as the exploitation method makes use of a vpointer that has not been initialized.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code and
  compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat version 9.2.0 and prior.

  Adobe Acrobat version 9.2.0 and prior.");

  script_tag(name:"solution", value:"Upgrade Adobe Reader version 9.3.2 or later.

  Workaround: Disable JavaScript execution from the Adobe Acrobat/Reader product
  configuration menu settings.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.f-secure.com/weblog/archives/00001836.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37331");
  script_xref(name:"URL", value:"http://extraexploit.blogspot.com/search/label/CVE-2009-4324");
  script_xref(name:"URL", value:"http://www.shadowserver.org/wiki/pmwiki.php/Calendar/20091214");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/12/new_adobe_reader_and_acrobat_v.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/adobe_media_newplayer.rb");
  script_xref(name:"URL", value:"http://vrt-sourcefire.blogspot.com/2009/12/adobe-reader-medianewplayer-analysis.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
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

if(version_is_less_equal(version:vers, test_version:"9.2.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 9.2.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
