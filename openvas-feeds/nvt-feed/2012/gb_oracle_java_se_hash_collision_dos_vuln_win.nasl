# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802681");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2012-2739");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-12-04 15:27:32 +0530 (Tue, 04 Dec 2012)");
  script_name("Oracle Java SE Hash Collision DoS Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51236");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/06/17/1");
  script_xref(name:"URL", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=750533");
  script_xref(name:"URL", value:"http://armoredbarista.blogspot.de/2012/02/investigating-hashdos-issue.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a denial of service
  condition via crafted input to an application that maintains a hash table.");
  script_tag(name:"affected", value:"Oracle Java SE 7 to 7 Update 5");
  script_tag(name:"insight", value:"The flaw is due to computes hash values without restricting the ability to
  trigger hash collisions predictably.");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 7 Update 6");
  script_tag(name:"summary", value:"Oracle Java SE is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer) {
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.5")) {
    report = report_fixed_ver(installed_version:jreVer, vulnerable_range:"1.7 - 1.7.0.5");
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
