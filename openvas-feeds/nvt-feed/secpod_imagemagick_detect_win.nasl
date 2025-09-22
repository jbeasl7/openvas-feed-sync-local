# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900562");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_name("ImageMagick Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  ImageMagick.

  The script logs in via smb, searches for ImageMagick in the registry
  and gets the version from 'DisplayName' string from registry.");

  script_tag(name:"qod_type", value:"registry");
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

if(!registry_key_exists(key:"SOFTWARE\ImageMagick") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\ImageMagick")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
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
    imName = registry_get_sz(key:key + item, item:"DisplayName");
    if("ImageMagick" >< imName)
    {
      imVer = eregmatch(pattern:"ImageMagick ([0-9.]+\-?[0-9]{0,3})", string:imName);
      if(imVer[1] != NULL)
      {
        imVer[1] = ereg_replace(pattern:"-", string:imVer[1], replace: ".");
        imPath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!imPath){
          imPath = "Unable to find the install location from registry";
        }
      }

      set_kb_item(name:"ImageMagick/Win/Installed", value:TRUE);

      if("64" >< os_arch && "Wow6432Node" >!< key) {
        set_kb_item(name:"ImageMagick64/Win/Ver", value:imVer[1]);
        base = "cpe:/a:imagemagick:imagemagick:x64:";
      } else {
        set_kb_item(name:"ImageMagick/Win/Ver", value:imVer[1]);
        base = "cpe:/a:imagemagick:imagemagick:";
      }

      register_and_report_cpe( app: "ImageMagick",
                               ver: imVer[1],
                               concluded: imVer[0],
                               base: base,
                               expr: "^([0-9.]+)",
                               insloc: imPath );
      exit( 0 );
    }
  }
}
