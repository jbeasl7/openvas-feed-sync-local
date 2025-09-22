# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801824");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-4217");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IBM Tivoli Directory Proxy Server Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44604");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2861");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Nov/1024670.html");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IO13364");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IO13282");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_mandatory_keys("IBM/TDS/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash an affected server,
  creating a denial of service condition.");
  script_tag(name:"affected", value:"IBM Tivoli Directory Server (TDS) 6.0.0.x before 6.0.0.8-TIV-ITDS-IF0007
  and 6.1.x before 6.1.0-TIV-ITDS-FP0005.");
  script_tag(name:"insight", value:"The flaw is caused by an error in the Proxy server when constructing LDAP
  search requests, which could allow remote attackers to crash an affected
  server by sending an unbind operation during a page results search.");
  script_tag(name:"solution", value:"Apply interim fix 6.0.0.8-TIV-ITDS-IF0007 or 6.1.0-TIV-ITDS-FP0005.");

  script_tag(name:"summary", value:"IBM Tivoli Directory Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

tdsVer = get_kb_item("IBM/TDS/Ver");
if(!tdsVer){
  exit(0);
}

if(version_in_range(version: tdsVer, test_version: "6.0", test_version2:"6.0.0.8") ||
   version_in_range(version: tdsVer, test_version: "6.1", test_version2:"6.1.0.5")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
