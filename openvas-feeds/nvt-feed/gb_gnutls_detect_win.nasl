# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800916");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-02-03 13:43:16 +0530 (Mon, 03 Feb 2014)");
  script_name("GnuTLS Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of GnuTLS on Windows.

  The script logs in via smb, searches for GnuTLS in the registry
  and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

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

## if os is 32 bit iterate over common path
if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    gnuTLSName = registry_get_sz(key:key + item, item:"DisplayName");

    if("GnuTLS" >< gnuTLSName)
    {

      gnuTLSVers = registry_get_sz(key:key + item, item:"DisplayVersion");
      gnuTLSPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!gnuTLSPath){
        gnuTLSPath = "Could not find the install location from registry";
      }

      if(gnuTLSVers)
      {
        set_kb_item(name:"openssl_or_gnutls/detected", value:TRUE);
        set_kb_item(name:"gnutls/detected", value:TRUE);
        if("x64" >< osArch && "Wow6432Node" >!< key) {
          register_and_report_cpe( app:"GnuTLS", ver:gnuTLSVers, base:"cpe:/a:gnu:gnutls:x64:", expr:"^([0-9.]+)", insloc:gnuTLSPath, regPort:0, regService:"smb-login" );
        } else {
          register_and_report_cpe( app:"GnuTLS", ver:gnuTLSVers, base:"cpe:/a:gnu:gnutls:", expr:"^([0-9.]+)", insloc:gnuTLSPath, regPort:0, regService:"smb-login" );
        }

        ## To improve performance by avoiding extra iteration over uninstall path
        exit(0);
      }
    }
  }
}
