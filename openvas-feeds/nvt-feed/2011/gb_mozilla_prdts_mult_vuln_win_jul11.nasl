# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802213");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (Jul 2011) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-23.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48360");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48376");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-24.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to disclose potentially
  sensitive information, execute arbitrary code or cause a denial of service.");
  script_tag(name:"affected", value:"SeaMonkey versions 2.0.14 and prior.
  Thunderbird version before 3.1.11.
  Mozilla Firefox versions before 3.6.18.");
  script_tag(name:"insight", value:"- Multiple use-after-free errors allows remote attackers to cause a denial
    of service or possibly execute arbitrary code.

  - An error in the way cookies are handled could lead to bypass the Same
    Origin Policy via Set-Cookie headers.");
  script_tag(name:"summary", value:"Mozilla Firefox, Seamonkey or Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.18 or later,
  Upgrade to Seamonkey version 2.2 or later,
  Upgrade to Thunderbird version 3.1.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");


vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.6.18"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.18");
    security_message(port: 0, data: report);
    exit(0);
  }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  if(version_is_less_equal(version:smVer, test_version:"2.0.14"))
  {
    report = report_fixed_ver(installed_version:smVer, vulnerable_range:"Less than or equal to 2.0.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_is_less(version:vers, test_version:"3.1.11")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.11");
    security_message(port: 0, data: report);
  }
}
