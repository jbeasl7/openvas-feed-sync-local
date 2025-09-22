# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902142");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0163");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Mozilla Products Denial Of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56993");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38831");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0648");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-07.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
  or possibly execute arbitrary code via a crafted message, related to message indexing.");

  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.19 and
  Thunderbird version prior to 2.0.0.24 on Windows.");

  script_tag(name:"insight", value:"The flaw exists when processing e-mail attachments with a parser that performs
  casts and line termination incorrectly, which allows remote attackers to crash the application.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.19 or later

  Upgrade to Thunderbird version 2.0.0.24 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Thunderbird/Seamonkey is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"1.1.19")){
     report = report_fixed_ver(installed_version:smVer, fixed_version:"1.1.19");
     security_message(port: 0, data: report);
     exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"2.0.0.24")){
    report = report_fixed_ver(installed_version:tbVer, fixed_version:"2.0.0.24");
    security_message(port: 0, data: report);
  }
}

exit(99);
