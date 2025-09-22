# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900728");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1569", "CVE-2009-1568");
  script_name("Novell iPrint Client Multiple BOF Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_lin.nasl");
  script_mandatory_keys("Novell/iPrint/Client/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation lets the remote attacker have a control over
  the remote system registers allowing execution of malformed shellcode.");
  script_tag(name:"affected", value:"Novell iPrint Client version prior to 5.32");
  script_tag(name:"insight", value:"Multiple flaws are due to inadequate boundary checks on user supplied
  inputs while the application processes the input data into the application
  context.");
  script_tag(name:"solution", value:"Upgrade Novell iPrint Client version to 5.32.");
  script_tag(name:"summary", value:"Novell iPrint Client is prone to multiple Buffer Overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37169");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37242");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-40/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3429");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=29T3EFRky18~");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508288/100/0/threaded");
  exit(0);
}

include("version_func.inc");

iPrintVer = get_kb_item("Novell/iPrint/Client/Linux/Ver");
if(!iPrintVer)
  exit(0);

if(version_is_less(version:iPrintVer, test_version:"5.32")){
  report = report_fixed_ver(installed_version:iPrintVer, fixed_version:"5.32");
  security_message(port: 0, data: report);
}
