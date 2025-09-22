# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902712");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2137",
                "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2138",
                "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414",
                "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417",
                "CVE-2011-2425", "CVE-2011-2424");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Air and Flash Player Multiple Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49075");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49080");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49086");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"Adobe Air versions prior to 2.7.1
  Adobe Flash Player versions prior to 10.3.183.5");
  script_tag(name:"insight", value:"Multiple flaws are caused by memory corruptions, cross-site information
  disclosure, buffer overflow and integer overflow errors.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.5 and Adobe Air version
  2.7.1 or later.");
  script_tag(name:"summary", value:"Adobe Air and/or Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(flashVer)
{
  if(version_is_less(version:flashVer, test_version:"10.3.183.5"))
  {
    report = report_fixed_ver(installed_version:flashVer, fixed_version:"10.3.183.5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
  if(version_is_less(version:airVer, test_version:"2.7.1")){
    report = report_fixed_ver(installed_version:airVer, fixed_version:"2.7.1");
    security_message(port: 0, data: report);
  }
}
