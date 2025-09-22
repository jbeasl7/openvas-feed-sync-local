# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800514");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_name("GraphicsMagick Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  GraphicsMagick.

  The script logs in via smb, searches for Graphics Magick in the registry
  and gets the version from 'Version' string from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick:";

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\GraphicsMagick") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\GraphicsMagick")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\GraphicsMagick\Current");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\GraphicsMagick\Current",
                        "SOFTWARE\Wow6432Node\GraphicsMagick\Current");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  gmVer = registry_get_sz(key:key, item:"Version");
  if(gmVer)
  {
    gmPath = registry_get_sz(key:key, item:"ConfigurePath");
    if(!gmPath){
      gmPath = "Unable to find the install location from registry";
    }

    set_kb_item(name:"GraphicsMagick/Win/Installed", value:TRUE);

    if("64" >< os_arch && "Wow6432Node" >!< key) {
      set_kb_item(name:"GraphicsMagick64/Win/Ver", value:gmVer);
      CPE += "x64:";
    } else {
      set_kb_item(name:"GraphicsMagick/Win/Ver", value:gmVer);
    }

    register_and_report_cpe(app:"GraphicsMagick",
                            ver:gmVer,
                            base:CPE,
                            expr:"^([0-9.]+)",
                            insloc:gmPath,
                            regService:"smb");


  }
}

exit(0);
