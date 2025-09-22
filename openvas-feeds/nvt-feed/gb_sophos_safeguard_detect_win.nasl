# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107326");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-07-02 15:11:48 +0200 (Mon, 02 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sophos SafeGuard Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"Detects the installed version of Sophos SafeGuard on Windows.
  The script logs in via smb, searches for Sophos SafeGuard in the registry
  and gets the version from the 'DisplayVersion' string.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include ("cpe.inc");
include ("host_details.inc");
include ("smb_nt.inc");
include ("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if (!registry_key_exists(key:"SOFTWARE\Wow6432Node\Sophos") && !registry_key_exists(key:"SOFTWARE\Sophos") && !registry_key_exists(key:"SOFTWARE\Utimaco") && !registry_key_exists(key:"SOFTWARE\Wow6432Node\Utimaco"))
  exit(0);

if ("x86" >< os_arch)
{
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}
else if ("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list))
  exit(0);

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz (key:key + item, item:"DisplayName");

    if ("Preinstall" >< appName) continue;

    # nb: The exact DisplayNames of LAN Crypt and Easy Crypt have yet to be determined.
    if ("LAN Crypt" >< appName && "Sophos" >< appName)
    {
      base = "cpe:/a:sophos:safeguard_lan_crypt_encryption_client:";
      app = "Sophos SafeGuard LAN Crypt Client";
    }
    else if ("Easy" >< appName && "Sophos" >< appName)
    {
      base = "cpe:/a:sophos:safeguard_easy_device_encryption_client:";
      app = "Sophos SafeGuard Easy Client";
    }
    else if ("Sophos SafeGuard Client" >< appName)
    {
      base = "cpe:/a:sophos:safeguard_enterprise_device_encryption_client:";
      app = "Sophos SafeGuard Enterprise Client";
    }
    else
    {
      continue;
    }

    version = registry_get_sz(key:key + item, item:"DisplayVersion");
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");

    if (version)
    {
      set_kb_item (name:"Sophos/SafeGuard/Win/Installed", value:TRUE);
      set_kb_item (name:"Sophos/SafeGuard/"+ app + "/Win/Installed", value:TRUE);

      if ("64" >< os_arch && "Wow6432Node" >!< key)
        base = base + "x64:";

      if (!insloc)
        insloc = "Install location unknown";

      register_and_report_cpe(app:app, ver:version, concluded:appName, base:base, expr:"^([0-9.]+)", insloc:insloc);
    }
  }
}

exit(0);
