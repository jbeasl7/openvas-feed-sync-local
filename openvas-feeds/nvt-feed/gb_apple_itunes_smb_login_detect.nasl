# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900123");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");

  script_name("Apple iTunes Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Apple iTunes.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apple_itunes_smb_login_wsc_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("keys/is_gef");

  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

# nb: No need to run the detection in GEF at all because the new gsf/gb_apple_itunes_smb_login_wsc_detect.nasl should run instead
if(get_kb_item("keys/is_gef"))
  exit(0);

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key))
  exit(0);

foreach item(registry_enum_keys(key:key)) {

  ituneName = registry_get_sz(key:key + item, item:"DisplayName");
  if(ituneName =~ "^(iTunes)$") {

    insPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insPath)
      insPath = "Could not find the install Location from registry";

    ituneVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ituneVer) {
      set_kb_item(name:"apple/itunes/detected", value:TRUE);
      set_kb_item(name:"apple/itunes/smb-login/detected", value:TRUE);

      register_and_report_cpe(app:ituneName, ver:ituneVer, base:"cpe:/a:apple:itunes:", expr:"^([0-9.]+)", insloc:insPath);

      if("64" >< os_arch) {
        set_kb_item(name:"apple/itunes/x64/detected", value:TRUE);
        register_and_report_cpe(app:ituneName, ver:ituneVer, base:"cpe:/a:apple:itunes:x64:", expr:"^([0-9.]+)", insloc:insPath);
      }
    }
    exit(0);
  }
}

exit(0);
