# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107359");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-01 14:20:47 +0100 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sophos HitmanPro.Alert x86 Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Sophos HitmanPro.Alert.");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("list_array_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

foreach key(make_list_unique("HitmanPro.Alert", registry_enum_keys(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))) {

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + key;
  if(!registry_key_exists(key:key))
    continue;

  appName = registry_get_sz(key:key, item:"DisplayName");
  if(!appName || appName !~ "HitmanPro\.Alert")
    continue;

  loc = registry_get_sz(key:key, item:"InstallLocation");
  ver = registry_get_sz(key:key, item:"DisplayVersion");

  set_kb_item(name:"Sophos/HitmanPro.Alert/Win/detected", value:TRUE);
  set_kb_item(name:"Sophos/HitmanPro.Alert/Win/Ver", value:ver);

  register_and_report_cpe(app:"Sophos " + appName, ver:ver,
                          base:"cpe:/a:sophos:hitmanpro.alert:", expr:"^([0-9.a-z-]+)", insloc:loc, regService:"smb-login", regPort:0);
  exit(0);
}

exit(0);
