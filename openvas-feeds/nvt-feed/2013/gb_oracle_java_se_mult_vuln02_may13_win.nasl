# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803487");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-2439", "CVE-2013-2432", "CVE-2013-2430", "CVE-2013-2394",
                "CVE-2013-2429", "CVE-2013-2424", "CVE-2013-2420", "CVE-2013-2419",
                "CVE-2013-2417", "CVE-2013-2384", "CVE-2013-2383", "CVE-2013-1569",
                "CVE-2013-1557", "CVE-2013-1537", "CVE-2013-1518");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-05-06 17:13:12 +0530 (Mon, 06 May 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -02 (May 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59141");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59154");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59170");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59178");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59187");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59243");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuapr2013verbose-1928687.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.");
  script_tag(name:"affected", value:"Oracle Java SE Version 7 Update 17 and earlier, 6 Update 43 and earlier
  and 5 Update 41 and earlier");
  script_tag(name:"insight", value:"Multiple flaws due to unspecified errors in the Install, 2D, JMX,
  Networking, RMI, JAXP and ImageIO components.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer && jreVer =~ "^(1\.(5|6|7))")
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.17")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.43")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.41"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
