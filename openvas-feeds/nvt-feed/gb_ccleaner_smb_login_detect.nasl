# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811777");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-19 11:52:53 +0530 (Tue, 19 Sep 2017)");

  script_name("CCleaner Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection CCleaner (Free and Professional Editions).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

# nb: The Key is the same for x86 and x64 Platforms
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner";
if(!registry_key_exists(key:key))
  exit(0);

appName = registry_get_sz(key:key, item:"DisplayName");
if("CCleaner" >< appName) {

  vers = "unknown";
  path = "unknown";

  insloc = registry_get_sz(key:key, item:"InstallLocation");
  if(insloc) {
    path = insloc;

    appVer = fetch_file_version(sysPath:insloc, file_name:"CCleaner.exe");
    # Remove the third version component to match the official format (e.g., "6.39.11548" from "6.39.0.11548")
    # https://www.ccleaner.com/ccleaner/version-history
    if( appVer && version_info = eregmatch( string:appVer, pattern:"^([0-9]+\.[0-9]+\.)[0-9]+\.([0-9]+)" ) ) {
      vers = version_info[1] + version_info[2];
      set_kb_item( name:"piriform/ccleaner/detected", value:TRUE );
      set_kb_item( name:"piriform/ccleaner/smb-login/detected", value:TRUE );
    }
  }

  cpe = build_cpe(value:vers, exp:"([0-9.]+)", base:"cpe:/a:piriform:ccleaner:");
  if(!cpe)
    cpe = "cpe:/a:piriform:ccleaner";

  if("x64" >< os_arch) {
    if(vers != "unknown")
      set_kb_item( name:"piriform/ccleanerx64/detected", value:TRUE );
      set_kb_item( name:"piriform/ccleanerx64/smb-login/detected", value:TRUE );

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:piriform:ccleaner:x64:");
    if(!cpe)
      cpe = "cpe:/a:piriform:ccleaner:x64";
  }

  # Used in gb_ccleaner_portable_smb_login_detect.nasl to avoid doubled detections.
  # We're also stripping a possible ending backslash away as the portable VT is getting
  # the file path without the ending backslash from WMI.
  tmp_location = tolower(path);
  tmp_location = ereg_replace(pattern:"\\$", string:tmp_location, replace:'');
  set_kb_item(name:"piriform/ccleaner/locations", value:tmp_location);

  register_product(cpe:cpe, location:path, port:0, service:"smb-login");
  log_message(port:0, data:build_detection_report(app:appName, version:vers, install:path, cpe:cpe, concluded:appVer + '\n\n'));
}

exit(0);
