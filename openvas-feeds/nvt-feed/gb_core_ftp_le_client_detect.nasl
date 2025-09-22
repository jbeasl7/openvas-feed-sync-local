# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810304");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-12-08 11:49:16 +0530 (Thu, 08 Dec 2016)");
  script_name("Core FTP LE Client Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of the Core FTP LE Client.");

  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

## Key based on architecture
if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

else if("x64" >< os_arch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  ftpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Core FTP LE" >< ftpName)
  {
    ftpPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(ftpPath)
    {
      ftpPath = ftpPath - "uninstall.exe";
      ftpPath = ereg_replace(pattern:'"', replace:"", string:ftpPath);

      ##coreftp.exe --> CoreFTP Client, coresrvr.exe --> CoreFTP server
      ftpVer = fetch_file_version(sysPath:ftpPath, file_name:"coreftp.exe");
    }
    else
    {
      ftpPath = "Could not find the install location from registry";
    }

    if(ftpVer)
    {
      set_kb_item(name:"Core/FTP/Client/Win/Ver", value:ftpVer);

      cpe = build_cpe(value:ftpVer, exp:"^([0-9.]+)", base:"cpe:/a:coreftp:core_ftp:");
      if(!cpe)
        cpe = "cpe:/a:coreftp:core_ftp";

      register_product(cpe:cpe, location:ftpPath);

      log_message(data: build_detection_report(app: "Core FTP LE",
                                               version: ftpVer,
                                               install: ftpPath,
                                               cpe: cpe,
                                               concluded: ftpVer));
    }
  }
}
