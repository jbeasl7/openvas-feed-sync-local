# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800750");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0181");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Mozilla Products Denial of Service Vulnerability - Windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57395");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0748");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-23.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  (excessive application launches) via an HTML document with many images.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.4 and
  Firefox version before 3.5.9, 3.6.x before 3.6.2 on Windows.");

  script_tag(name:"insight", value:"The flaw is caused by an error when handling an 'image' tag pointing to
  a resource that redirects to a 'mailto:' URL, an external mail handler application is launched.");

  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.9 or 3.6.2

  Upgrade to Seamonkey version 2.0.4");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
