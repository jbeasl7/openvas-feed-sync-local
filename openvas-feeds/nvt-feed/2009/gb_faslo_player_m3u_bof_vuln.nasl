# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900254");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3969");
  script_name("Fasloi Player .m3u Playlist Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9487");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36444/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2395");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_faslo_player_detect.nasl");
  script_mandatory_keys("FasloPlayer/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code by
tricking users into opening crafted m3u playlist files and may cause Denial
of Service.");
  script_tag(name:"affected", value:"Faslo Player version 7.0 on Windows.");
  script_tag(name:"insight", value:"A boundary error occurs when processing .m3u playlist files
containing overly long data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Faslo Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

fpVer = get_kb_item("FasloPlayer/Ver");
if(!fpVer){
  exit(0);
}

if(version_is_equal(version:fpVer, test_version:"7.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
