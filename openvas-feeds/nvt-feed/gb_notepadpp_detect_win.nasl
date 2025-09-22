# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805317");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-09 13:19:25 +0530 (Fri, 09 Jan 2015)");
  script_name("Notepad++ Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of
  Notepad++ on Windows.

  This script logs in via smb, searches for 'Notepad++' in the registry and
  gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++");
} else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++");
}

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list) {

  noteName = registry_get_sz(key:key, item:"DisplayName");
  if("Notepad++" >< noteName){

    noteVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(!noteVer){
      continue;
    }

    notePath = registry_get_sz(item:"UninstallString", key:key);
    if(!notePath){
      notePath = "Could not find the install location from registry";
    } else{
      notePath = notePath - "\uninstall.exe";
    }

    # Used in gb_notepadpp_detect_portable_win.nasl to avoid doubled detections.
    # We're also stripping a possible ending backslash away as the portable VT is getting
    # the file path without the ending backslash from WMI.
    tmp_location = tolower(notePath);
    tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
    set_kb_item(name:"Notepad++/Win/InstallLocations", value:tmp_location);

    if("x64" >< os_arch && "Wow6432Node" >!< key){
      base = "cpe:/a:notepad-plus-plus:notepad++:x64:";
      set_kb_item(name:"Notepad++64/Win/installed", value:TRUE);
      set_kb_item(name:"Notepad++32or64/Win/installed", value:TRUE);
    } else {
      base = "cpe:/a:notepad-plus-plus:notepad++:";
      set_kb_item(name:"Notepad++32/Win/installed", value:TRUE);
      set_kb_item(name:"Notepad++32or64/Win/installed", value:TRUE);
    }
    register_and_report_cpe(app:noteName, ver:noteVer, concluded:noteVer, base:base, expr:"^([0-9.]+)", insloc:notePath);
  }
}

exit(0);
