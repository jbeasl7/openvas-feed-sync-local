# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902333");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1676");
  script_name("Tor Unspecified Heap Based Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45500");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3290");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");
  script_tag(name:"affected", value:"Tor version prior to 0.2.1.28 and 0.2.2.x before 0.2.2.20-alpha on Windows.");
  script_tag(name:"insight", value:"The issue is caused by an unknown heap overflow error when processing
  user-supplied data, which can be exploited to cause a heap-based buffer
  overflow.");
  script_tag(name:"solution", value:"Upgrade to version 0.2.1.28 or 0.2.2.20-alpha or later.");
  script_tag(name:"summary", value:"Tor is prone to heap based buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the user running the application. Failed exploit
  attempts will likely result in denial-of-service conditions.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);

if(version_is_less(version:torVer, test_version:"0.2.1.28"))
{
  report = report_fixed_ver(installed_version:torVer, fixed_version:"0.2.1.28");
  security_message(port: 0, data: report);
  exit(0);
}

if(torVer =~ "^0\.2\.2.*")
{
  if(version_is_less(version:torVer, test_version:"0.2.2.20.alpha")){
    report = report_fixed_ver(installed_version:torVer, fixed_version:"0.2.2.20.alpha");
    security_message(port: 0, data: report);
  }
}
