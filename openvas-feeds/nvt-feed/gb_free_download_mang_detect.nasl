# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800348");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Free Download Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of Free Download Manager.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Free Download Manager Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

regPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Free Download Manager_is1",
                          item:"InstallLocation");
if(!regPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:regPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:regPath + "\fdm.exe");

fdmVer = GetVer(share:share, file:file);
if(fdmVer)
{
  set_kb_item(name:"FreeDownloadManager/Ver", value:fdmVer);
  log_message(data:"Free Download Manager version " + fdmVer + " running at" +
                     " location " + regPath + " was detected on the host");

  cpe = build_cpe(value:fdmVer, exp:"^([0-9]\.[0-9])", base:"cpe:/a:free_download_manager:free_download_manager:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
