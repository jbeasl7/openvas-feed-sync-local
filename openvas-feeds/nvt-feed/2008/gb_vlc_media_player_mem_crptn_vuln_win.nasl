# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800112");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4558");
  script_name("VLC Media Player XSPF Playlist Memory Corruption Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32267/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31758");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2826/products");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/vlc-xspf-memory-corruption");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into opening a specially crafted XSPF file or even can crash
  an affected application.");

  script_tag(name:"affected", value:"VLC media player 0.9.2 and prior Windows (Any).");

  script_tag(name:"insight", value:"The flaw exists due to VLC (xspf.c) library does not properly perform bounds
  checking on an identifier tag from an XSPF file before using it to index an array on the heap.");

  script_tag(name:"solution", value:"Upgrade to Version 0.9.3 or later.");

  script_tag(name:"summary", value:"VLC Media Player is prone to a memory corruption vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

vlcVer = registry_get_sz(item:"Version", key:"SOFTWARE\VideoLAN\VLC");
if(!vlcVer){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"0.9.2")){
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"Less than or equal to 0.9.2");
  security_message(port: 0, data: report);
}
