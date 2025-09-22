# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802581");
  script_version("2024-02-22T14:37:29+0000");
  script_cve_id("CVE-2012-0443", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-03 19:44:43 +0530 (Fri, 03 Feb 2012)");
  script_name("Mozilla Products Multiple Unspecified Vulnerabilities - 01 - (Feb 2012) - Windows");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51757");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51765");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-06.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.7
  Thunderbird version 5.0 through 9.0
  Mozilla Firefox version 4.x through 9.0");
  script_tag(name:"insight", value:"The flaws are due to n

  - Multiple unspecified vulnerabilities in browser engine.

  - An error in frame scripts bypass XPConnect security checks when calling
    untrusted objects.

  - Not properly initializing data for image/vnd.microsoft.icon images, which
    allows remote attackers to obtain potentially sensitive information by
    reading a PNG image that was created through conversion from an ICO image.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird/Seamonkey is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 10.0 or later.

  Upgrade to SeaMonkey version to 2.7 or later.

  Upgrade to Thunderbird version to 10.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!isnull(ffVer))
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"9.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"4.0 - 9.0");
    security_message(port:0, data:report);
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(!isnull(seaVer))
{
  if(version_is_less(version:seaVer, test_version:"2.7"))
  {
    report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.7");
    security_message(port:0, data:report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!isnull(tbVer))
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"9.0")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"5.0 - 9.0");
    security_message(port:0, data:report);
  }
}
