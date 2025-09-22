# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802980");
  script_version("2025-08-01T05:45:36+0000");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-10-10 10:36:03 +0530 (Wed, 10 Oct 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft FAST Search Server Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of Microsoft FAST Search Server.");
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

fsKey = "SOFTWARE\Microsoft\FAST Search Server";
if(!registry_key_exists(key:fsKey))
  exit(0);

fsKey = fsKey + "\Setup";
insPath = registry_get_sz(key:fsKey, item:"Path");
if(!insPath)
  insPath = "Could not find the install location from registry";

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key)) {

  fsName = registry_get_sz(key:key + item, item:"DisplayName");
  if(!fsName)
    continue;

  if("Microsoft FAST Search Server" >< fsName ) {
    ver = eregmatch(string:fsName, pattern:"([0-9]+)");

    fsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(fsVer) {

      set_kb_item(name:"microsoft/fast_search_server/detected", value:TRUE);
      set_kb_item(name:"microsoft/fast_search_server/smb-login/detected", value:TRUE);
      set_kb_item(name:"microsoft/fast_search_server/version", value:fsVer);
      set_kb_item(name:"microsoft/fast_search_server/smb-login/version", value:fsVer);
      set_kb_item(name:"microsoft/fast_search_server/install_path", value:insPath);
      set_kb_item(name:"microsoft/fast_search_server/smb-login/install_path", value:insPath);

      if(ver[0]) {
        cpe = build_cpe(value:fsVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:microsoft:fast_search_server_for_sharepoint:" + ver[0]);
      } else {
        cpe = build_cpe(value:fsVer, exp:"^([0-9.]+)",
                        base:"cpe:/a:microsoft:fast_search_server_for_sharepoint:");
      }

      if(!cpe)
        cpe = "cpe:/a:microsoft:fast_search_server_for_sharepoint";

      register_product(cpe:cpe, location:insPath, port:0, service:"smb-login");

      log_message(data:build_detection_report(app:"Microsoft Fast Search Server",
                                              version:fsVer, install:insPath, cpe:cpe,
                                              concluded:fsVer));
      exit(0);
    }
  }
}
