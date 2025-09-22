# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801754");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foxit Phantom Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the Foxit Phantom version.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Foxit Phantom Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Foxit Phantom";
if(!registry_key_exists(key:key)){
  exit(0);
}

name = registry_get_sz(key:key, item:"DisplayName");
if("Foxit Phantom" >< name)
{
  foxitVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(foxitVer == NULL){
    exit(0);
  }
}

set_kb_item(name:"foxit/phantom/ver", value:foxitVer);
set_kb_item(name:"foxit/phantom_or_reader/detected", value:TRUE);
log_message(data:"Foxit Phantom version " + foxitVer + " was detected on the host");

cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
if(!isnull(cpe))
   register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

