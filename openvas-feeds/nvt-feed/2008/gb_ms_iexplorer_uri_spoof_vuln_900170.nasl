# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900170");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31960");
  script_cve_id("CVE-2008-4787");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_name("Microsoft iExplorer '&NBSP;' Address Bar URI Spoofing Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"An attacker may leverage this issue to spoof the source URI of a site which leads
  to false sense of trust.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer versions 6.0 SP1 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to inadequately handling specific combinations
  of non-breaking space characters.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Internet Explorer is prone to an URI spoofing vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Internet Explorer";
iExpVer = registry_get_sz(key:key , item:"Version");
if(!iExpVer){
  iExpVer = registry_get_sz(key:key, item:"W2kVersion");
  if(!iExpVer){
    exit(0);
  }
}

if(ereg(pattern:"^6\.0", string:iExpVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
