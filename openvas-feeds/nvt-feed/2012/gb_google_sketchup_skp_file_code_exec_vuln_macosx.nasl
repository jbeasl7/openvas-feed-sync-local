# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902681");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-2478");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-21 14:56:42 +0530 (Mon, 21 May 2012)");
  script_name("Google SketchUp '.SKP' File Remote Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38187");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48363");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68147");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2011/msvr11-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_google_sketchup_detect_macosx.nasl");
  script_mandatory_keys("Google/SketchUp/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause SketchUp to exit
  unexpectedly and execute arbitrary code by tricking a user into opening a
  specially crafted '.SKP' file.");
  script_tag(name:"affected", value:"Google SketchUp version 7.1 Maintenance Release 2 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error when handling certain types of invalid
  edge geometry in a specially crafted SketchUp (.SKP) file.");
  script_tag(name:"solution", value:"Upgrade to Google SketchUp version 8.0 or later.");
  script_tag(name:"summary", value:"Google SketchUp is prone to a remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

gsVer = get_kb_item("Google/SketchUp/MacOSX/Version");
if(!gsVer){
  exit(0);
}

if(version_is_less_equal(version:gsVer, test_version:"7.1.6859")){
  report = report_fixed_ver(installed_version:gsVer, vulnerable_range:"Less than or equal to 7.1.6859");
  security_message(port:0, data:report);
}
