# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.817135");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-05-27 12:17:09 +0530 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Edge (Chromium-based) Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version
  of Microsoft Edge (Chromium-based) for Windows.");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("cpe.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Edge")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Edge")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe");
}


foreach key(key_list)
{
  exePath = registry_get_sz(key: key, item:"Path");
  if(exePath)
  {
    edgeVer = fetch_file_version(sysPath: exePath, file_name: "msedge.exe");
    if(!edgeVer){
      edgeVer = "Unknown";
    }

    if(edgeVer)
    {
      set_kb_item(name:"microsoft_edge_chromium/ver", value:edgeVer);
      set_kb_item(name:"microsoft_edge_chromium/installed", value:TRUE);

      ##No CPE found, currently creating new one
      register_and_report_cpe( app:"Microsoft Edge (Chromium-based)", ver:edgeVer, base:"cpe:/a:microsoft:edge_chromium_based:", expr:"^([0-9.]+)", insloc:exePath, regService:"smb-login", regPort:0 );

      if("64" >< os_arch && "Wow6432Node" >!< key && "x86" >!< exePath)
      {
        set_kb_item(name:"microsoft_edge_chromium64/ver", value:edgeVer);
        register_and_report_cpe( app:"Microsoft Edge (Chromium-based)", ver:edgeVer, base:"cpe:/a:microsoft:edge_chromium_based:x64:", expr:"^([0-9.]+)", insloc:exePath, regService:"smb-login", regPort:0 );
      }
      exit(0);
    }
  }
}
