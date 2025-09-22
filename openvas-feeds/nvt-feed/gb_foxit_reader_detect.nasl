# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800536");
  script_version("2024-06-21T15:40:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_name("Foxit Reader Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Foxit Reader.

  The script logs in via smb, searches for Foxit Reader in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"executable_version");
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
  key_list = make_list("SOFTWARE\Foxit Software\Foxit Reader", "SOFTWARE\Foxit Software\Foxit PDF Reader");
} else if("x64" >< os_arch){
  #nb: Currently only 32-bit application is available
  key_list = make_list("SOFTWARE\Wow6432Node\Foxit Software\Foxit Reader", "SOFTWARE\Wow6432Node\Foxit Software\Foxit PDF Reader");
}

if(isnull(key_list)){
  exit(0);
}

foreach key(key_list){
  if(registry_key_exists(key: key)){
    found = TRUE;
    break;
  }
}

if(!found){
  exit(0);
}

foreach key(key_list){
  foxitVer = registry_get_sz(key:key, item:"Version");
  foxitPath = registry_get_sz(key:key, item:"InstallPath");
  if(!foxitPath){
    foxitPath = registry_get_sz(key:key, item:"InstallLocation");
  }

  if(!foxitVer){
    if(foxitPath){
      foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
      if(!foxitVer){
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitReader.exe");
      }
      if(!foxitVer){
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitPDFReader.exe");
      }
    }else {
      foxitPath = registry_get_sz(key:key, item:"InnoSetupUpdatePath");
      if(foxitPath){
        foxitPath = foxitPath - "unins000.exe";
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
      }
      if(!foxitVer){
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitReader.exe");
      }
      if(!foxitVer){
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitPDFReader.exe");
      }
    }
  }

  if(foxitVer){

    set_kb_item(name:"foxit/phantom_or_reader/detected", value:TRUE);
    set_kb_item(name:"foxit/reader/ver", value:foxitVer);

    if(!foxitPath){
      foxitPath = 'Could not find the install path from registry';
    }

    # Used in gb_foxit_reader_detect_portable_win.nasl to avoid doubled detections.
    # We're also stripping a possible ending backslash away as the portable VT is getting
    # the file path without the ending backslash from WMI.
    tmp_location = tolower(foxitPath);
    tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
    set_kb_item(name:"foxit/reader/win/install_locations", value:tmp_location);

    cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
    if(isnull(cpe))
      cpe = "cpe:/a:foxitsoftware:reader";

    register_product(cpe:cpe, location:foxitPath);

    log_message(data:build_detection_report(app:"Foxit Reader",
                                            version:foxitVer,
                                            install:foxitPath,
                                            cpe:cpe,
                                            concluded:foxitVer));
  }
}

exit(0);
