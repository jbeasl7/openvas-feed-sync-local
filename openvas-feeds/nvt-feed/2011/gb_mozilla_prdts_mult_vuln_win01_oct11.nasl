# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802175");
  script_version("2024-02-22T14:37:29+0000");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3866");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities - 01 - (Oct 2011) - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46171/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49813");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-41.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-45.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to, attackers to cause a denial
  of service (memory corruption and application crash) or possibly execute
  arbitrary code.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.4
  Mozilla Firefox version prior to 7");
  script_tag(name:"insight", value:"The flaws are due to

  - An error while validating the return value of a GrowAtomTable function
    call.

  - An error within WebGL's ANGLE library does not properly check for return
    values from the 'GrowAtomTable()' function and can be exploited to cause
    a buffer overflow by sending a series of requests.

  - Error while restricting availability of motion data events.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 7.0 or later, Upgrade to SeaMonkey version to 2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"7.0"))
  {
     report = report_fixed_ver(installed_version:vers, fixed_version:"7.0");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.4")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.4");
    security_message(port: 0, data: report);
  }
}
