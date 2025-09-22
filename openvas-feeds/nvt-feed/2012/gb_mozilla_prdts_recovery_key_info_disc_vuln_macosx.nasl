# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802582");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-02-06 14:03:00 +0530 (Mon, 06 Feb 2012)");
  script_cve_id("CVE-2012-0450");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mozilla Products 'Firefox Recovery Key.html' Information Disclosure Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-09.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51787");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to read a Firefox Sync key via
  standard filesystem operations and gain sensitive information.");
  script_tag(name:"affected", value:"SeaMonkey version prior to 2.7
  Mozilla Firefox version 4.x through 9.0");
  script_tag(name:"insight", value:"The flaw is due to setting weak permissions for Firefox Recovery
  Key.html, which might allow local users to read a Firefox Sync key via
  standard filesystem operations.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey is prone to an information disclosure vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 10.0 or  later, Upgrade to SeaMonkey version to 2.7 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"9.0"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 9.0");
     security_message(port:0, data:report);
     exit(0);
  }
}

vers = get_kb_item("SeaMonkey/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"2.7")){
     report = report_fixed_ver(installed_version:vers, fixed_version:"2.7");
     security_message(port:0, data:report);
  }
}
