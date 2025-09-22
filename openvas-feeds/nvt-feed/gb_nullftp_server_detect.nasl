# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800545");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NULL FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script finds the installed NULL FTP Server version.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

SCRIPT_DESC = "NULL FTP Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Null FTP Server" >< appName)
  {
    nullftpVer = eregmatch(pattern:"Null FTP Server ([0-9.]+)", string:appName);
    nullftpVer = nullftpVer[1];
    if(nullftpVer == NULL)
    {
      exePath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!exePath){
        exit(0);
      }

      exePath = exePath + "NullFtpServer.exe";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

      nullftpVer = GetVer(file:file, share:share);
    }

    if(nullftpVer != NULL)
    {
      set_kb_item(name:"NullFTP/Server/Ver", value:nullftpVer);
      log_message(data:"NULL FTP Server version " + nullftpVer +
                    " running at location " + exePath + " was detected on the host");

      cpe = build_cpe(value: nullftpVer, exp:"^([0-9.]+)",base:"cpe:/a:vwsolutions:null_ftp:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}
