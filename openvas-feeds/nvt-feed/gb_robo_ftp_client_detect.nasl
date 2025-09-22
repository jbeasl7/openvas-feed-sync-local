# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801053");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Robo-FTP Client Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed Robo-FTP Client version.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Robo-FTP" >< name)
  {
    ftpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!isnull(ftpVer))
    {
      set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);

      register_and_report_cpe(app:"Robo-FTP Client", ver:ftpVer, base:"cpe:/a:robo-ftp:robo-ftp:",
                              expr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?");
      exit(0);
    }
  }
}

path = registry_get_sz(key:"SOFTWARE\Robo-FTP", item:"InstallDir");
if(path != NULL)
{
  ftpVer = fetch_file_version(sysPath:path, file_name:"Robo-FTP.exe");
  if(!isnull(ftpVer))
  {
    set_kb_item(name:"Robo/FTP/Ver", value:ftpVer);

    register_and_report_cpe(app:"Robo-FTP Client", ver:ftpVer, base:"cpe:/a:robo-ftp:robo-ftp:",
                            expr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", insloc:path);
    exit(0);
  }
}
