# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802479");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2012-5085", "CVE-2012-5084", "CVE-2012-5073", "CVE-2012-5077",
                "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-10-19 12:43:54 +0530 (Fri, 19 Oct 2012)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities - 02 - (Oct 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50949/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56080");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56082");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50949");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code on
  the target system or cause complete denial of service conditions.");
  script_tag(name:"affected", value:"Oracle Java SE 7 Update 7 and earlier, 6 Update 35 and earlier,
  5.0 Update 36 and earlier and 1.4.2_38 and earlier");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exist in the application related
  to 2D, Networking, Swing, Libraries, Security and JSSE.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.38") ||
     version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.7") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.35") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.36")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
