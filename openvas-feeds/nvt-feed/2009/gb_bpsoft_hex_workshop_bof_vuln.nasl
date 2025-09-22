# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800528");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0812");
  script_name("BreakPoint Software, Hex Workshop Buffer Overflow vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33932");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8121");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_bpsoft_hex_workshop_detect.nasl");
  script_mandatory_keys("BPSoft/HexWorkshop/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary
  code and can cause denial-of-service.");
  script_tag(name:"affected", value:"BreakPoint Software, Hex Workshop version 6.0.1.4603 and prior on Windows.");
  script_tag(name:"insight", value:"Application fails to adequately sanitize user input data, which in turn
  leads to boundary error while processing of Intel .hex files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Hex Workshop is prone to a stack-based buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

hwVer = get_kb_item("BPSoft/HexWorkshop/Ver");
if(!hwVer){
  exit(0);
}

if(version_is_less_equal(version:hwVer, test_version:"6.0.1.4603")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
