# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902524");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867",
                "CVE-2011-0871", "CVE-2011-0873", "CVE-2011-0802", "CVE-2011-0814",
                "CVE-2011-0815", "CVE-2011-0862");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities (Jun 2011) - Windows");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48145");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48149");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"Oracle Java SE versions 6 Update 25 and prior, 5.0 Update 29 and prior,
  and 1.4.2_31 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - 2D

  - AWT

  - Sound

  - Swing

  - HotSpot

  - Networking

  - Deserialization

  - Java Runtime Environment");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 6 Update 26, 5.0 Update 30, 1.4.2_32
  or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  ## and 1.4.2_31 and prior
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.31") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.25") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.29"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  ## and 1.4.2_31 and prior
  if(version_is_less_equal(version:jdkVer, test_version:"1.4.2.31") ||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.25") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.29")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
