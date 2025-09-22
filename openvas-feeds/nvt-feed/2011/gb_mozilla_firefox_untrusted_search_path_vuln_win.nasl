# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802149");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2980");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Untrusted Search Path Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49217");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 3.6.20");
  script_tag(name:"insight", value:"The flaw is due to error in 'ThinkPadSensor::Startup' allows local
  users to gain privileges by leveraging write access in an unspecified
  directory to place a Trojan horse DLL that is loaded into the running
  Firefox process.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.20 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to untrusted search path vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.6.20")){
     report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.6.20");
     security_message(port: 0, data: report);
     exit(0);
  }
}
