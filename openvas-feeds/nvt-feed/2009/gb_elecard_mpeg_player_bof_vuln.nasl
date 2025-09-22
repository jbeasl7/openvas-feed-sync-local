# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800511");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0491");
  script_name("Elecard MPEG Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33355");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33089");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7637");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_elecard_mpeg_player_detect.nasl");
  script_mandatory_keys("Elecard/Player/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes in the context of the application and may cause stack overflow in
  the application.");
  script_tag(name:"affected", value:"Elecard MPEG Player 5.5 build 15884.081218 and prior.");
  script_tag(name:"insight", value:"Issue is with boundary error while processing playlist 'm3u' files, which
  may contain crafted long URLs.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Elecard MPEG Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

epVer = get_kb_item("Elecard/Player/Ver");
if(epVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:epVer, test_version:"5.5.15884.081218")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
