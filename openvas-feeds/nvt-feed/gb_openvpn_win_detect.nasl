# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107309");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-05-09 14:19:44 +0200 (Wed, 09 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("OpenVPN Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detects the installed version of OpenVPN on Windows.
  The script logs in via smb, searches for OpenVPN in the registry
  and gets the version from 'DisplayName' string in registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include ("cpe.inc");
include ("host_details.inc");
include ("smb_nt.inc");
include ("secpod_smb_func.inc");

os_arch = get_kb_item ("SMB/Windows/Arch");
if (!os_arch){
 exit (0);
}

appKey_list = make_list ("SOFTWARE\OpenVPN", "SOFTWARE\Wow6432Node\OpenVPN",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenVPN");
foreach appKey (appKey_list)
{

 if (registry_key_exists(key:appKey))
  {
    appExists = TRUE;
    break;
  }
}

if (!appExists) exit(0);

if ("x86" >< os_arch){
  key_list = make_list ("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if ("x64" >< os_arch)
{
  key_list =  make_list ("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
 }

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz (key:key + item, item:"DisplayName");
    if ("OpenVPN" >< appName)
    {
      appVer = eregmatch (pattern:"OpenVPN (([0-9.]+)(-I60[12])?)", string:appName);
      appVer = ereg_replace (pattern:" ", replace:":", string:appVer[1]);
      if (appVer != NULL)
      {
        insloc = registry_get_sz (key:key + item, item:"InstallLocation");
        if (!insloc)
            insloc = "Unable to find the install location";

        set_kb_item (name:"OpenVPN/Win/Ver", value:appVer);

        cpe = build_cpe (value:appVer, exp:"^([0-9.]+):?([a-z]+)?", base:"cpe:/a:openvpn:openvpn:");
        if (isnull(cpe))
          cpe = "cpe:/a:openvpn:openvpn";

        if ("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item (name:"OpenVPN64/Win/Ver", value:appVer);

          cpe = build_cpe (value:appVer, exp:"^([0-9.]+):?([a-z]+)?", base:"cpe:/a:openvpn:openvpn:x64:");
          if (isnull(cpe))
            cpe = "cpe:/a:openvpn:openvpn:x64";
        }

        register_product (cpe:cpe, location:insloc);

        log_message (data: build_detection_report (app: appName,
                                           version: appVer,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: appVer));

      }
    }
  }
}
