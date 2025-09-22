# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800038");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Wireshark Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Wireshark on Windows.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

## For 64 bit app also key is creating under Wow6432Node
else if("x64" >< os_arch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key))
  exit(0);

wireName = registry_get_sz(key:key + "Wireshark", item:"DisplayName");

if("Wireshark" >< wireName) {

  wiresharkVer = registry_get_sz(key:key + "Wireshark", item:"DisplayVersion");

  path = registry_get_sz(key:key + "Wireshark", item:"UninstallString");
  if(path)
    path = path - "\uninstall.exe";
  else
    path = "Unable to find the install location from registry.";

  if(wiresharkVer) {

    set_kb_item(name:"wireshark/detected", value:TRUE);
    set_kb_item(name:"wireshark/windows/detected", value:TRUE);

    cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(!cpe)
      cpe = "cpe:/a:wireshark:wireshark";

    if("64" >< os_arch && "64-bit" >< wireName) {

      set_kb_item(name:"wireshark/windows/64/detected", value:TRUE);

      cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:x64:");
      if(!cpe)
        cpe = "cpe:/a:wireshark:wireshark:x64";
    }

    register_product(cpe:cpe, location:path, port:0, service:"smb-login");

    log_message(data:build_detection_report(app:wireName,
                                            version:wiresharkVer,
                                            install:path,
                                            cpe:cpe,
                                            concluded:wiresharkVer),
                port:0);
  }
}

exit(0);
