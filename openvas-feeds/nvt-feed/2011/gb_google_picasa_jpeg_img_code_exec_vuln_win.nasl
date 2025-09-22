# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802313");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2747");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Picasa JPEG Image Processing Remote Code Execution Vulnerability - Windows");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_mandatory_keys("Google/Picasa/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code or cause a denial of service condition.");
  script_tag(name:"affected", value:"Google Picasa versions prior to 3.6 build 105.67");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error, when handling certain
  properties of an image file and can be exploited via a specially crafted
  JPEG image.");
  script_tag(name:"solution", value:"Upgrade to the Google Picasa 3.6 build 105.67 or later.");
  script_tag(name:"summary", value:"google picasa is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45293");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48725");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/msvr11-008.mspx");
  script_xref(name:"URL", value:"http://picasa.google.com/support/bin/static.py?hl=en&page=release_notes.cs&from=53209&rd=1");
  script_xref(name:"URL", value:"http://picasa.google.com/thanks.html");
  exit(0);
}


include("version_func.inc");

picVer = get_kb_item("Google/Picasa/Win/Ver");
if(!picVer){
  exit(0);
}

if(version_is_less(version:picVer, test_version:"3.6.105.67")){
  report = report_fixed_ver(installed_version:picVer, fixed_version:"3.6.105.67");
  security_message(port: 0, data: report);
}
