# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803307");
  script_version("2024-02-16T05:06:55+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0431", "CVE-2013-1489", "CVE-2013-0351", "CVE-2013-0409",
                "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2012-3342",
                "CVE-2012-3213", "CVE-2012-1541", "CVE-2013-1475", "CVE-2013-0425",
                "CVE-2013-0426", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449",
                "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1476", "CVE-2013-1478",
                "CVE-2013-1479", "CVE-2013-1480", "CVE-2013-0435", "CVE-2013-0434",
                "CVE-2013-0433", "CVE-2013-0432", "CVE-2013-0430", "CVE-2013-0429",
                "CVE-2013-0428", "CVE-2013-0437", "CVE-2013-0438", "CVE-2013-1481",
                "CVE-2013-0445", "CVE-2013-0444", "CVE-2013-0443", "CVE-2013-0442",
                "CVE-2013-0441", "CVE-2013-0440", "CVE-2013-0427");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-06 18:29:04 +0530 (Wed, 06 Feb 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -01 (Feb 2013) - Windows");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57686");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57692");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57704");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57707");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57708");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57710");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57712");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57713");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57714");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57717");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57726");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57730");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57731");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.");
  script_tag(name:"affected", value:"Oracle Java SE Version 7 Update 11 and earlier, 6 Update 38 and earlier,
  5 Update 38 and earlier and 1.4.2_40 and earlier.");
  script_tag(name:"insight", value:"Multiple flaws due to unspecified errors in the following components:

  - Deployment

  - Scripting

  - COBRA

  - Sound

  - Beans

  - 2D

  - Networking

  - Libraries

  - Installation process of client

  - Abstract Window Toolkit (AWT)

  - Remote Method Invocation (RMI)

  - Java Management Extensions (JMX)

  - Java API for XML Web Services(JAX_WS)

  - Java Secure Socket Extension (JSSE)");
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
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.40")||
     version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.11")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.38")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.38"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
