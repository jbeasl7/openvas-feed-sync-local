# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812919");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-02-15 11:59:46 +0530 (Thu, 15 Feb 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Acrobat DC (Continuous Track) Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of
  Adobe Acrobat DC (Continuous Track).

  The script logs in via smb, searches for 'Adobe Acrobat DC' in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://acrobat.adobe.com/us/en/acrobat.html");

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
    adobeName = registry_get_sz(key:key + item, item:"DisplayName");
    adobePath = registry_get_sz(key:key + item, item:"InstallLocation");

    if("Adobe Acrobat DC" >< adobeName && "Acrobat DC" >< adobePath)
    {
      adobeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(adobeVer)
      {
        set_kb_item(name:"Adobe/AcrobatDC/Continuous/Win/Ver", value:adobeVer);

        ## New cpe created
        cpe = build_cpe(value:adobeVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_dc_continuous:");
        if(!cpe)
          cpe = "cpe:/a:adobe:acrobat_dc_continuous";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Adobe/AcrobatDC/Continuous64/Win/Ver", value:adobeVer);
          cpe = build_cpe(value:adobeVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:acrobat_dc_continuous:x64:");
          if(!cpe)
            cpe = "cpe:/a:adobe:acrobat_dc_continuous:x64";
        }

        register_product(cpe:cpe, location:adobePath);
        log_message(data: build_detection_report(app:"Adobe Acrobat DC (Continuous Track)", version: adobeVer,
                                                 install: adobePath, cpe:cpe, concluded:adobeVer));
        exit(0);
      }
    }
  }
}
exit(0);
