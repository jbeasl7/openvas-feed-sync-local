# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800966");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Perl Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Active or Strawberry Perl.

The script logs in via smb, searches for Active or Strawberry Perl in the
registry and gets the version from registry");

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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    perlName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Strawberry Perl" >< perlName)
    {
      perlLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!perlLoc)
      {
        perlLoc = "Location not found";
      }

      perlVer = registry_get_sz(key:key + item, item:"Comments");
      perlVer = eregmatch(pattern:"Strawberry Perl .* ([0-9.]+)", string:perlVer);
      if(!isnull(perlVer[1]))
      {

        set_kb_item(name:"Strawberry/Perl/Loc", value:perlLoc);
        set_kb_item( name:"Perl/Strawberry_or_Active/Installed", value:TRUE );

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Strawberry64/Perl/Ver", value:perlVer[1]);
          register_and_report_cpe( app:"Strawberry Perl", ver:perlVer[1], base:"cpe:/a:vanilla_perl_project:strawberry_perl:x64:", expr:"^([0-9.]+)", insloc:perlLoc );
        } else {
          set_kb_item(name:"Strawberry/Perl/Ver", value:perlVer[1]);
          register_and_report_cpe( app:"Strawberry Perl", ver:perlVer[1], base:"cpe:/a:vanilla_perl_project:strawberry_perl:", expr:"^([0-9.]+)", insloc:perlLoc );
        }
      }
    }

    if("ActivePerl"  >< perlName)
    {
      perlLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!perlLoc){
        perlLoc = "Location not found";
      }

      perlVer = eregmatch(pattern:"ActivePerl ([0-9.]+)", string:perlName);
      if(!isnull(perlVer[1]))
      {
        set_kb_item(name:"ActivePerl/Loc", value:perlLoc);
        set_kb_item( name:"Perl/Strawberry_or_Active/Installed", value:TRUE );

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"ActivePerl64/Ver", value:perlVer[1]);
          register_and_report_cpe( app:"Active Perl", ver:perlVer[1], base:"cpe:/a:perl:perl:x64:", expr:"^([0-9.]+)", insloc:perlLoc );
        } else {
          set_kb_item(name:"ActivePerl/Ver", value:perlVer[1]);
          register_and_report_cpe( app:"Active Perl", ver:perlVer[1], base:"cpe:/a:perl:perl:", expr:"^([0-9.]+)", insloc:perlLoc );
        }
      }
    }
  }
}
