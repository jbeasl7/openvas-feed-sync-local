# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107397");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-12-03 14:46:08 +0100 (Mon, 03 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("INVT Electric VT Designer Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  # nb: While CVEs / advisories are using "VT-Designer" the vendor itself is actually using no dash
  # as seen on e.g. the download page of the product.
  script_tag(name:"summary", value:"SMB login-based detection of INVT Electric VT Designer.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if (!os_arch)
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if ("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list))
  exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if(!appName || appName !~ "VT Designer")
      continue;

    version = "unknown";
    concluded += "INVT Electric VT Designer";
    location = "unknown";

    loc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(loc)
      location = loc;

    vers = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(vers) {
      version = vers;
      concluded += " " + vers;
    }

    set_kb_item(name:"invt_electric/vt_designer/detected", value:TRUE);
    set_kb_item(name:"invt_electric/vt_designer/smb-login/detected", value:TRUE);

    register_and_report_cpe(app:"INVT Electric VT Designer", ver:version, concluded:concluded,
                            base:"cpe:/a:invt:vt-designer:", expr:"^([0-9.]+)",
                            insloc:location, regService:"smb-login", regPort:0);

    exit(0);
  }
}

exit(0);
