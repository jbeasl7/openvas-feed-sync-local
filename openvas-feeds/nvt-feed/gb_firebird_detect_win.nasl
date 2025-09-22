# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800851");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Firebird SQL Detection (Windows SMB Login)");


  script_tag(name:"summary", value:"Detects the installed version of Firebird SQL on Windows.

The script logs in via smb, searches for Firebird SQL in the registry
and gets the version from 'DisplayVersion' string in registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Firebird Project\Firebird Server")||
   registry_key_exists(key:"SOFTWARE\Wow6432Node\Firebird Project\Firebird Server"))
{
  if("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  }
  else if("x64" >< os_arch)
  {
    key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  }

  if(isnull(key_list)){
    exit(0);
  }

  foreach key (key_list)
  {
    foreach item (registry_enum_keys(key:key))
    {
      firebirdName = registry_get_sz(key:key + item, item:"DisplayName");
      if(firebirdName =~ "Firebird [0-9.]+")
      {
        firebirdVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        insloc = registry_get_sz(key:key + item, item:"InstallLocation");

        if(!firebirdVer)
        {
          if(!insloc){
            insloc = "Unable to find the install location";
          } else {
            firebirdVer = fetch_file_version(sysPath: insloc + "bin", file_name: "fbserver.exe");
          }
        }

        if(firebirdVer)
        {
          set_kb_item(name:"Firebird-SQL/Ver", value:firebirdVer);

          cpe = build_cpe(value:firebirdVer, exp:"^([0-9.]+)", base:"cpe:/a:firebirdsql:firebird:");
          if(isnull(cpe))
            cpe = "cpe:/a:firebirdsql:firebird";

          if("64" >< os_arch && "Wow6432Node" >!< key)
          {
            set_kb_item(name:"Firebird-SQL64/Ver", value:firebirdVer);

            cpe = build_cpe(value:firebirdVer, exp:"^([0-9.]+)", base:"cpe:/a:firebirdsql:firebird:x64:");
            if(isnull(cpe))
              cpe = "cpe:/a:firebirdsql:firebird:x64";
          }

          register_product(cpe:cpe, location:insloc);
          log_message(data: build_detection_report(app: "Firebird",
                                                   version: firebirdVer,
                                                   install: insloc,
                                                   cpe: cpe,
                                                   concluded: firebirdVer));
        }
      }
    }
  }
}
