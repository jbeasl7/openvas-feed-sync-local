# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800883");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Mozilla Detection (Windows SMB Login)");


  script_tag(name:"summary", value:"Detects the installed version of Mozilla on Windows.

The script logs in via smb, searches for Mozilla in the registry and gets
the version from registry.");

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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  path = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Mozilla.exe";
}

else if("x64" >< osArch){
  path = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\Mozilla.exe";
}

if(!registry_key_exists(key:path)){
  exit(0);
}

mozillaName = registry_get_sz(key:path, item:"Path");
if("mozilla.org" >< mozillaName)
{
  mozillaPath = mozillaName + "\mozilla.exe";

  mozillaVer = GetVersionFromFile(file:mozillaPath, verstr:"prod");

  if(!isnull(mozillaVer))
  {
    set_kb_item(name:"Mozilla/Win/Ver", value:mozillaVer);
    set_kb_item( name:"Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed", value:TRUE );

    cpe = build_cpe(value:mozillaVer, exp:"^([0-9.]+)", base:"cpe:/a:mozilla:mozilla:");
    if(isnull(cpe))
      cpe = "cpe:/a:mozilla:mozilla";

    register_product(cpe: cpe, location: path, port:0, service:"smb-login");
    log_message(data: build_detection_report(app: "Mozilla Browser",
                                             version: mozillaVer,
                                             install: path,
                                                 cpe: cpe,
                                           concluded: mozillaVer));


  }
}
exit(0);
