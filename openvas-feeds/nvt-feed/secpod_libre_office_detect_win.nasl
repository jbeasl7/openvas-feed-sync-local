# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902398");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of LibreOffice on Windows.

  The script logs in via smb, searches for LibreOffice in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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

if(!registry_key_exists(key:"SOFTWARE\LibreOffice")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\LibreOffice")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list){

  foreach item (registry_enum_keys(key:key)){

    officeName = registry_get_sz(key:key + item, item:"DisplayName");

    if("LibreOffice" >< officeName){

      officeVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!isnull(officeVer)){
        officePath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!officePath){
          officePath = "Could not able to get the install location";
        }

        set_kb_item(name:"LibreOffice/Win/Ver", value:officeVer);

        cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:");
        if(isnull(cpe))
          cpe = "cpe:/a:libreoffice:libreoffice";

        if("64" >< os_arch && "Wow6432Node" >!< key){

          set_kb_item(name:"LibreOffice64/Win/Ver", value:officeVer);
          cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:x64:");

          if(isnull(cpe))
            cpe = "cpe:/a:libreoffice:libreoffice:x64";
        }

        # Used in gb_libreoffice_detect_portable_win.nasl to avoid doubled detections.
        # We're also stripping a possible ending backslash away as the portable VT is getting
        # the file path without the ending backslash from WMI.
        tmp_location = tolower(officePath);
        tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
        set_kb_item(name:"LibreOffice/Win/InstallLocations", value:tmp_location);

        register_product(cpe:cpe, location:officePath);
        log_message(port:0, data:build_detection_report(app:officeName, version:officeVer, install:officePath, cpe:cpe, concluded:officeVer));
      }
    }
  }
}

exit(0);
