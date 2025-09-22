# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802432");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-14 15:41:01 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Internet Information Services (IIS) Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Microsoft Internet Information Services (IIS).");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\Microsoft\InetStp";
if(!registry_key_exists(key:key))
  exit(0);

iisName = registry_get_sz(key:key, item:"ProductString");
if("Microsoft Internet Information Services" >< iisName) {

  iisVer = registry_get_sz(key:key, item:"VersionString");
  if(iisVer) {
    iisVerString = eregmatch(pattern:"Version ([0-9.]+)", string:iisVer);
    if(iisVerString[1]) {
      set_kb_item(name:"MS/IIS/Ver", value:iisVerString[1]);
      path = registry_get_sz(key:key, item:"InstallPath");
      if(!path)
        path = "Could not find the install path from registry";

      cpe = build_cpe(value:iisVerString[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:internet_information_services:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:path, port:0, service:"smb-login");

      log_message(data:build_detection_report(app:"Microsoft Internet Information Services (IIS)",
                  version:iisVerString[1], install:path, cpe:cpe, concluded:iisVerString[1]));
    }
  }
}
