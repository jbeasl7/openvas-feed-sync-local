# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802273");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3552", "CVE-2011-3556",
                "CVE-2011-3557", "CVE-2011-3560");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)");
  script_name("Oracle Java SE 1.4, 5, 6, 7 Multiple Vulnerabilities (cpuoct2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50248");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java SE versions 7, 6 Update 27 and earlier, 5.0 Update 31 and earlier,
  and 1.4.2_33 and earlier.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - Networking

  - AWT

  - RMI

  - JSSE");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE versions 7 Update 1, 6 Update 29, 5.0 Update
  32, 1.4.2_34 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  ## 5.0 Update 31 and earlier, and 1.4.2_33 and earlier
  if(version_is_equal(version:jreVer, test_version:"1.7.0") ||
     version_is_less_equal(version:jreVer, test_version:"1.4.2.33") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.27") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.31"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  ## 5.0 Update 31 and earlier, and 1.4.2_33 and earlier
  if(version_is_equal(version:jdkVer, test_version:"1.7.0") ||
     version_is_less_equal(version:jdkVer, test_version:"1.4.2.33") ||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.27") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.31")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
