# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800273");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_cve_id("CVE-2009-1257");
  script_name("Magic ISO Maker Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34595");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8343");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0940");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_magic_iso_maker_detect.nasl");
  script_mandatory_keys("MagicISOMaker/Ver");
  script_tag(name:"affected", value:"Magic ISO Maker version 5.5 build 274 and prior.");
  script_tag(name:"insight", value:"This flaw is due to inadequate boundary check while processing 'CCD'
  image files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Magic ISO Maker is prone to Heap-Based Buffer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in
  the context of the application and can cause Heap Overflow.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

magicVer = get_kb_item("MagicISOMaker/Ver");
if(!magicVer){
  exit(0);
}

if(version_is_less_equal(version:magicVer, test_version:"5.5.0274")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
