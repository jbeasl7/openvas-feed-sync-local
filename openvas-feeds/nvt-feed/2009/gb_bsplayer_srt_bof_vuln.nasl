# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800270");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6583");
  script_name("BSPlayer Stack Overflow Vulnerability SRT");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5455");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28811");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41841");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/1243/references");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_bsplayer_detect.nasl");
  script_mandatory_keys("BSPlayer/Ver");
  script_tag(name:"affected", value:"BSPlayer version 2.27.958 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to boundary check error while the user supplies input data
  in the context of the application.");
  script_tag(name:"solution", value:"Upgrade to BSPlayer version 2.27.958 or later.");
  script_tag(name:"summary", value:"BSPlayer Free Edition is prone to Stack Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious arbitrary
  'srt' file and cause stack overflow in the context of the affected
  application or can also cause remote code execution.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.bsplayer.org");
  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("BSPlayer/Ver");
if(playerVer != NULL)
{
  if(version_is_less_equal(version:playerVer, test_version:"2.27.958")){
    report = report_fixed_ver(installed_version:playerVer, vulnerable_range:"Less than or equal to 2.27.958");
    security_message(port: 0, data: report);
  }
}
