# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809453");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-10-17 16:22:36 +0530 (Mon, 17 Oct 2016)");
  script_name("HPE Sizing for Microsoft Lync Server Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  HPE Sizing Tool for Microsoft Lync Server.

  The script logs in via smb, searches for 'HPE Sizing Tool for Microsoft Lync Server'
  in the registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

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
if(!os_arch){
  exit(0);
}

##Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  if("HPE Sizer for Microsoft Lync Server" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!hpPath){
        hpPath = "Could not find the install location from registry";
      }

      set_kb_item(name:"HPE/sizer/microsoft/lync/server", value:hpVer);

      if("Lync Server 2010" >< hpName) {
        register_and_report_cpe( app:hpName, ver:hpVer, base:"cpe:/a:hp:sizer_for_microsoft_lync_server_2010:", expr:"^([0-9.]+)", insloc:hpPath );
      }
      if("Lync Server 2013" >< hpName) {
        register_and_report_cpe( app:hpName, ver:hpVer, base:"cpe:/a:hp:sizer_for_microsoft_lync_server_2013:", expr:"^([0-9.]+)", insloc:hpPath );
      }
    }
  }
}
exit(0);
