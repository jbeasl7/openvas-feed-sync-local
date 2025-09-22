# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800807");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ICQ Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of ICQ Client.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "ICQ Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!(registry_key_exists(key:"SOFTWARE\Mirabilis\ICQ") ||
     registry_key_exists(key:"SOFTWARE\ICQ"))){
  exit(0);
}

# To Get the Installed Location
icqPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                              "\App Paths\ICQ.exe", item:"Path");
if(icqPath == NULL){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:icqPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:icqPath + "\icq.exe");
icqVer = GetVer(share:share, file:file);

if(icqVer != NULL)
{
  set_kb_item(name:"ICQ/Ver", value:icqVer);
  log_message(data:"ICQ version " + icqVer + " running at location" + icqPath +
                     " was detected on the host");

  cpe = build_cpe(value:icqVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:icq:icq:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
