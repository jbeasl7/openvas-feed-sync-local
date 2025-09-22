# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903203");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1484", "CVE-2013-1485", "CVE-2013-1486", "CVE-2013-1487");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-02-22 13:41:39 +0530 (Fri, 22 Feb 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -02 (Feb 2013) - Windows");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028155");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58031");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2013update-1905892.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.");
  script_tag(name:"affected", value:"Oracle Java SE Version 7 Update 13 and earlier, 6 Update 39 and earlier,
  5 Update 39 and earlier.");
  script_tag(name:"insight", value:"Multiple flaws due to unspecified errors in the following components:

  - Deployment

  - Libraries

  - Java Management Extensions (JMX)");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.13")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.39")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.39"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
