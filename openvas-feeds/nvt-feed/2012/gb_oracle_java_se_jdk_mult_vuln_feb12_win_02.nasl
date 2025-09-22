# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803335");
  script_version("2024-02-22T14:37:29+0000");
  script_cve_id("CVE-2012-0497", "CVE-2012-0500", "CVE-2012-0504");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 17:17:17 +0530 (Tue, 21 Feb 2012)");
  script_name("Oracle Java SE JDK Multiple Vulnerabilities - 02 - (Feb 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52015");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52020");
  script_xref(name:"URL", value:"http://www.pre-cert.de/advisories/PRE-SA-2012-01.txt");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java SE JDK 7 Update 2 and earlier, 6 Update 30 and earlier");
  script_tag(name:"insight", value:"Multiple flaws are caused by unspecified errors in the following
  components:

  - 2D

  - Install

  - Deployment");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE JDK versions 7 Update 3, 6 Update 31 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Java SE JDK is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer && jdkVer=~ "^(1.6|1.7)")
{
  if(version_in_range(version:jdkVer, test_version:"1.7", test_version2:"1.7.0.2")||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.30")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
