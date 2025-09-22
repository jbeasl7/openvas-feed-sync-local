# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800867");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672",
                "CVE-2009-2673", "CVE-2009-2675", "CVE-2009-2475",
                "CVE-2009-2689");
  script_name("Sun Java JDK/JRE Multiple Vulnerabilities (Aug 2009)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35939");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35944");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36162");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36180");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36199");
  script_xref(name:"URL", value:"http://java.sun.com/javase/6/webnotes/6u15.html");
  script_xref(name:"URL", value:"http://java.sun.com/j2se/1.5.0/ReleaseNotes.html");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263408-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263409-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263488-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125136-16-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125139-16-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-118667-22-1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl", "gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win_or_Linux/installed");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attacker to gain privileges via
  untrusted applet or Java Web Start application in the context of the affected system.");

  script_tag(name:"affected", value:"Sun Java JDK/JRE version 6 before Update 15 or 5.0 before Update 20");



  script_tag(name:"summary", value:"Sun Java JDK/JRE is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to JDK/JRE version 6 Update 15 or 5 Update 20.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");

if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.19")||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.14"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(isnull(jreVer))
{
  jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");
  if(isnull(jreVer))
    exit(0);
}

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.19")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.14")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
