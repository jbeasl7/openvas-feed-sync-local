# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802947");
  script_version("2024-02-27T14:36:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0507");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-22 15:52:21 +0530 (Wed, 22 Aug 2012)");
  script_name("Oracle Java SE Java Runtime Environment Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52161");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");
  script_xref(name:"URL", value:"http://www.metasploit.com/modules/exploit/multi/browser/java_atomicreferencearray");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to bypass the Java sandbox
  restriction and execute arbitrary code.");
  script_tag(name:"affected", value:"Oracle Java SE versions 7 Update 2 and earlier, 6 Update 30 and earlier,
  and 5.0 Update 33 and earlier");
  script_tag(name:"insight", value:"The 'AtomicReferenceArray' class implementation does not ensure that the
  array is of the Object[] type, which allows attackers to cause a denial of
  service (JVM crash) or bypass Java sandbox restrictions.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to a code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  ## 5.0 Update 31 and earlier
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.2") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.30") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.33")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
