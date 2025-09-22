# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802788");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2012-2026", "CVE-2012-2025", "CVE-2012-2024", "CVE-2012-2023",
                "CVE-2012-0780", "CVE-2012-2042");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-16 17:55:09 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Illustrator Multiple Unspecified Vulnerabilities - Mac OS X");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53422");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027047");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  or cause denial of service.");
  script_tag(name:"affected", value:"Adobe Illustrator version CS5.5 (15.1) on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in the
  application.");
  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Apply patch for Adobe Illustrator CS5 and CS5.5, or upgrade to Adobe Illustrator version CS6 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-10.html");
  exit(0);
}

include("version_func.inc");

illuVer = get_kb_item("Adobe/Illustrator/MacOSX/Version");
if(!illuVer){
  exit(0);
}

## Adobe Illustrator CS5.5 (15.1.1) and CS5 (15.0.3)
if(version_is_less(version:illuVer, test_version:"15.0.3"))
{
  report = report_fixed_ver(installed_version:illuVer, fixed_version:"15.0.3");
  security_message(port:0, data:report);
  exit(0);
}

if("15.1" >< illuVer)
{
  if(version_is_less(version:illuVer, test_version:"15.1.1")){
    report = report_fixed_ver(installed_version:illuVer, fixed_version:"15.1.1");
    security_message(port:0, data:report);
  }
}
