# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902774");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3658");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-22 11:48:05 +0530 (Thu, 22 Dec 2011)");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_name("Mozilla Products DOMAttrModified Memory Corruption Vulnerability - Windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51138");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-55.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely
  result in denial-of-service conditions.");
  script_tag(name:"affected", value:"SeaMonkey version 2.5
  Thunderbird version 8.0
  Mozilla Firefox version 8.0");
  script_tag(name:"insight", value:"The flaw is due to error in SVG implementation which results in an
  out-of-bounds memory access if SVG elements were removed during a
  DOMAttrModified event handler.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to out of bounds memory corruption vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 9.0 or later, Upgrade to SeaMonkey version to 2.6 or later,
  Upgrade to Thunderbird version to 9.0 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"8.0"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 8.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"2.5"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 2.5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_equal(version:vers, test_version:"8.0")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 8.0");
    security_message(port: 0, data: report);
  }
}
