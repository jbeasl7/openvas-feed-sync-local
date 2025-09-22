# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812870");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-05-02 16:59:41 +0530 (Wed, 02 May 2018)");
  script_name("Kaspersky Password Manager Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of Kaspersky
  password manager. The script logs in via smb, searches for Kaspersky password
  manager in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");

  script_xref(name:"URL", value:"https://www.kaspersky.co.in/password-manager");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch)
  exit(0);

if("x86" >< osArch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

else if("x64" >< osArch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

if(isnull(key))
  exit(0);

foreach item (registry_enum_keys(key:key)) {

  kname = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kaspersky Password Manager" >< kname) {
    version = "unknown";
    kver = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(kver)
      version = kver;

    kpath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!kpath)
      kpath = "Unable to find the install location from registry";

    set_kb_item(name:"kaspersky/password_manager/detected", value:TRUE);

    cpe = build_cpe(value:kver, exp:"^([0-9.]+)", base:"cpe:/a:kaspersky:password_manager:");
    if(!cpe)
      cpe = "cpe:/a:kaspersky:password_manager";

    register_product(cpe:cpe, location:kpath, port:0, service:"smb-login");
    log_message(data:build_detection_report(app:"Kaspersky Password Manager",
                                            version:version,
                                            install:kpath,
                                            cpe:cpe,
                                            concluded:kver));
    exit(0);
  }
}

exit(0);
