# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802592");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2012-0452");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-14 15:40:12 +0530 (Tue, 14 Feb 2012)");
  script_name("Mozilla Products XBL Binding Memory Corruption Vulnerability (MFSA2012-10) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48008/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51975");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026665");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.7.1,
  Thunderbird version 10.x prior to 10.0.1 and
  Mozilla Firefox version 10.x prior to 10.0.1 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in the 'ReadPrototypeBindings()' method
  when handling XBL bindings in a hash table and can be exploited to cause a
  cycle collector to call an invalid virtual function.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey/Thunderbird is prone to a memory corruption vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 10.0.1 or later, upgrade to SeaMonkey version to 2.7.1 or later,
  upgrade to Thunderbird version 10.0.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"10.0"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 10.0");
     security_message(port:0, data:report);
     exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"2.7"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 2.7");
    security_message(port:0, data:report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"10.0")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 10.0");
    security_message(port:0, data:report);
  }
}
