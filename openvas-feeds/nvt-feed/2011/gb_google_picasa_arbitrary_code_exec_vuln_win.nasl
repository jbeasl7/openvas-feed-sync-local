# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801770");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-0458");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Picasa Insecure Library Loading Arbitrary Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47031");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN99977321/index.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0766");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000022.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_mandatory_keys("Google/Picasa/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the user running the affected application.");
  script_tag(name:"affected", value:"Google Picasa versions prior to 3.8");
  script_tag(name:"insight", value:"The flaw is due to an error when loading executable and library files
  while using the 'Locate on Disk' feature.");
  script_tag(name:"solution", value:"Upgrade to the Google Picasa 3.8 or later.");
  script_tag(name:"summary", value:"Google Picasa is prone to an arbitrary code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://picasa.google.com/thanks.html");
  exit(0);
}


include("version_func.inc");

picVer = get_kb_item("Google/Picasa/Win/Ver");
if(!picVer){
  exit(0);
}

if(version_is_less(version:picVer, test_version:"3.8")){
  report = report_fixed_ver(installed_version:picVer, fixed_version:"3.8");
  security_message(port: 0, data: report);
}
