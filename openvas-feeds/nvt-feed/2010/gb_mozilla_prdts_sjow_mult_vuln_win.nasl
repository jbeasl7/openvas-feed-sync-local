# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801451");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-2763");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mozilla Products 'SJOW' Multiple Vulnerabilities (MFSA2010-60) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-60.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/firefox36.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass the same origin policy
  and conduct cross-site scripting attacks via a crafted function.");

  script_tag(name:"affected", value:"Firefox before 3.5.12

  SeaMonkey before 2.0.7

  Thunderbird before 3.0.7");

  script_tag(name:"insight", value:"The flaw is due to error in 'XPCSafeJSObjectWrapper' class in the
  'SafeJSObjectWrapper', which does not properly restrict scripted functions.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird are prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.12 or later

  Upgrade to Seamonkey version 2.0.7 or later

  Upgrade to Thunderbird version 3.0.7");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.5.12"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.5.12");
    security_message(port: 0, data: report);
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.7"))
  {
    report = report_fixed_ver(installed_version:smVer, fixed_version:"2.0.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"3.0.7")){
    report = report_fixed_ver(installed_version:tbVer, fixed_version:"3.0.7");
    security_message(port: 0, data: report);
  }
}
