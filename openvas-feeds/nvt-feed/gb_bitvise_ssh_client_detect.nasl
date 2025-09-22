# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813385");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-06-04 13:54:02 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Client Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of the Bitvise SSH Client.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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
if(!os_arch)
  exit(0);

if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

##Currently only 32-bit application is available
else if("x64" >< os_arch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  bitName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Bitvise SSH Client" >< bitName)
  {
    bitPath = registry_get_sz(key:key + item, item:"InstallSource");
    if(!bitPath){
      bitPath = "Could not find the install location from registry";
    }

    bitVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(bitVer)
    {
      set_kb_item(name:"BitviseSSH/Client/Win/Ver", value:bitVer);

      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitvise:ssh_client:");
      if(!cpe)
        cpe = "cpe:/a:bitvise:ssh_client";

      register_product(cpe:cpe, location:bitPath);

      log_message(data: build_detection_report(app: "Bitvise SSH Client",
                                               version: bitVer,
                                               install: bitPath,
                                               cpe: cpe,
                                               concluded: "Bitvise SSH Client " + bitVer));
    }
  }
}
exit(0);
