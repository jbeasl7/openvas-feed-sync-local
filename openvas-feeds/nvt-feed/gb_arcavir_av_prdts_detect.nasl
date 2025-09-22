# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800719");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ArcaVir AntiVirus Products Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of ArcaVir AntiVirus Products on Windows.

The script logs in via smb, searches for ArcaVir in the registry
and gets the install version from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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

key = "SOFTWARE\ArcaBit";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\ArcaBit";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    arcaName = registry_get_sz(key:key + item, item:"DisplayName");

    if("ArcaVir" >< arcaName || "Arcabit" >< arcaName)
    {
      arcaPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      if(arcaPath && "arcabit.exe" >< arcaPath){
        arcaPath = arcaPath - "arcabit.exe";
      }

      arcaVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!arcaVer && arcaPath){
        arcaVer = fetch_file_version(sysPath:arcaPath, file_name:"arcabit.exe");
      }
      if(arcaVer != NULL)
      {
        if(!arcaPath){
          arcaPath = "Could not find the install Location from registry";
        }
        set_kb_item(name:"ArcaVir/AntiVirus/Ver", value:arcaVer);

        ## 2009 version is not available for download
        ## Latest version is 2014, so haven't changed the cpe setting.
        cpe = build_cpe(value:arcaVer, exp:"^(9\..*)", base:"cpe:/a:arcabit:arcavir_2009_antivirus_protection:");
        if(isnull(cpe))
          cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"ArcaVir64/AntiVirus/Ver", value:arcaVer);

          cpe = build_cpe(value:arcaVer, exp:"^(9\..*)", base:"cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64";
        }
        register_product(cpe:cpe, location:arcaPath);

        log_message(data: build_detection_report(app: arcaName,
                                           version: arcaVer,
                                           install: arcaPath,
                                           cpe: cpe,
                                           concluded: arcaVer));

      }
    }
  }
}
