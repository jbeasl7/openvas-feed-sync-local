# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902242");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3131");
  script_name("Mozilla Products Insecure Library Loading Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41095");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14783/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2169");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513324/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary code and conduct DLL hijacking attacks.");

  script_tag(name:"affected", value:"Thunderbird version 3.1.2

  SeaMonkey version 2.0.6

  Firefox version 3.6.8 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers to
  execute arbitrary code by tricking a user into opening a file.");

  script_tag(name:"solution", value:"Upgrade Thunderbird to 3.1.3 or later

  Upgrade SeaMonkey to 2.0.7 or later

  Upgrade Firefox 3.6.9 or later");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to insecure library loading vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less_equal(version:ffVer, test_version:"3.6.8"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"Less than or equal to 3.6.8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less_equal(version:smVer, test_version:"2.0.6"))
  {
    report = report_fixed_ver(installed_version:smVer, vulnerable_range:"Less or equal to 2.0.6");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less_equal(version:tbVer, test_version:"3.1.2")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"Less or equal to 3.1.2");
    security_message(port: 0, data: report);
  }
}
