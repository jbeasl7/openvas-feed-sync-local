# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902545");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("IBM Informix Dynamic Server Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ibm_informix_dynamic_server_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("keys/is_gef");

  script_tag(name:"summary", value:"SMB login-based detection of IBM Informix Dynamic Server.");

  script_xref(name:"URL", value:"https://www.ibm.com/products/informix");

  exit(0);
}

# nb: No need to run the detection in GEF at all because the new gsf/gb_ibm_informix_dynamic_server_smb_login_detect.nasl should run instead
if (get_kb_item("keys/is_gef"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if (!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if (!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if (!registry_key_exists(key: "SOFTWARE\IBM\IBM Informix Dynamic Server") &&
    !registry_key_exists(key: "SOFTWARE\Wow6432Node\IBM\IBM Informix Dynamic Server") &&
    !registry_key_exists(key: "SOFTWARE\Informix"))
  exit(0);

if ("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
} else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if (isnull(key_list))
  exit(0);

foreach key (key_list) {
  foreach item (registry_enum_keys(key: key)) {
    display_name = registry_get_sz(key: key + item, item: "DisplayName");
    if (!display_name || "Informix Dynamic Server" >!< display_name)
      continue;

    concluded  = "  Registry Key:   " + key + item + '\n';
    concluded += "  DisplayName:    " + display_name + '\n';
    install_location = "unknown";

    if (loc = registry_get_sz(key: key + item, item: "InstallLocation"))
      install_location = loc;

    if (!display_version = registry_get_sz(key: key + item, item: "DisplayVersion"))
      display_version = "unknown";

    concluded += "  DisplayVersion: " + display_version;

    set_kb_item(name: "ibm/informix/dynamic_server/detected", value: TRUE);
    set_kb_item(name: "ibm/informix/dynamic_server/smb-login/detected", value: TRUE);

    cpe = build_cpe(value: display_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:informix_dynamic_server:");
    if (!cpe)
      cpe = "cpe:/a:ibm:informix_dynamic_server";

    register_product(cpe: cpe, location: install_location, port: 0, service: "smb-login");

    log_message(data: build_detection_report(app: "IBM Informix Dynamic Server", version: display_version,
                                             install: install_location, cpe: cpe, concluded: concluded),
                port: 0);
    exit(0);
  }
}

exit(0);
