# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801424");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-3106");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client Multiple Security Vulnerabilities - Linux");

  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-06");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42100");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-05");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-139/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-140/");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_lin.nasl");
  script_mandatory_keys("Novell/iPrint/Client/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  delete all files on a system in the context of an affected site.");

  script_tag(name:"affected", value:"Novell iPrint Client version 5.40 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Failure to properly verify the name of parameters passed via '<embed>'
    tags.

  - Error in handling plugin parameters. A long value for the operation
    parameter can trigger a stack-based buffer overflow.");

  script_tag(name:"summary", value:"Novell iPrint Client is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced links.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=ftwZBxEFjIg~");

  exit(0);
}

include("version_func.inc");

iPrintVer = get_kb_item("Novell/iPrint/Client/Linux/Ver");
if(!iPrintVer){
  exit(0);
}

if(version_is_less_equal(version:iPrintVer, test_version:"5.40.0")){
  report = report_fixed_ver(installed_version:iPrintVer, vulnerable_range:"Less than or equal to 5.40.0");
  security_message(port: 0, data: report);
}
