# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802513");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-3655");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-14 12:22:15 +0530 (Mon, 14 Nov 2011)");
  script_name("Mozilla Products 'NoWaiverWrapper' Privilege Escalation Vulnerability - Mac OS X");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-52.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50594");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to gain privileges via a crafted
  web site.");
  script_tag(name:"affected", value:"Thunderbird version 5.0 through 7.0
  Mozilla Firefox version 4.x through 7.0 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to: performing access control without checking for
  use of the NoWaiverWrapper wrapper, which allows remote attackers to gain
  privileges via a crafted web site.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird is prone to a privilege escalation vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 8.0 or later, Upgrade to Thunderbird version to 8.0 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"7.0"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 7.0");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_in_range(version:vers, test_version:"5.0", test_version2:"7.0")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.0 - 7.0");
    security_message(port: 0, data: report);
  }
}
