# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902525");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0872", "CVE-2011-0786",
                "CVE-2011-0788", "CVE-2011-0817", "CVE-2011-0863");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities - 01 - (Jun 2011) - Windows");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"Oracle Java SE versions 6 Update 25 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - 2D

  - NIO

  - SAAJ

  - Deployment");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 6 Update 26 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48138");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48140");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48141");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48146");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.25"))
  {
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"1.6 - 1.6.0.25");
    security_message(port: 0, data: report);
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.25")) {
     report = report_fixed_ver(installed_version:jdkVer, vulnerable_range:"1.6 - 1.6.0.25");
     security_message(port: 0, data: report);
     exit(0);
  }
}

exit(99);
