# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900799");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_name("Ruby Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Ruby.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

port = kb_smb_transport();

if("x86" >< os_arch) {
  key1_list = make_list("SOFTWARE\RubyInstaller\MRI\");
  key_list  = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch) {
  key1_list = make_list("SOFTWARE\RubyInstaller\MRI\",
                        "SOFTWARE\Wow6432Node\RubyInstaller\MRI\");
  key_list  = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Both 32 and 64 bit app registry is creating under wow6432node only.
## Tried installing Both 32 and 64 bit. Registry is not Creating Under uninstall Path.
## So Not able to test Under uninstall Path.
foreach key1(key1_list) {
  if(registry_key_exists(key:key1)) {
    foreach item (registry_enum_keys(key:key1)) {
      rubyLoc = registry_get_sz(key:key1 + item, item:"InstallLocation");
      if("Ruby" >< rubyLoc) {
        patch = registry_get_sz(key:key1 + item, item:"PatchLevel");
        build = registry_get_sz(key:key1 + item, item:"BuildPlatform");

        if(patch) {
          rubyVer = item + "." + patch;
          set_kb_item(name:"ruby/detected", value:TRUE);
          set_kb_item(name:"ruby/smb-login/detected", value:TRUE);
          set_kb_item(name:"ruby/smb-login/port", value:port);
          set_kb_item(name:"ruby/smb-login/" + port + "/install", value:"0#---#" + rubyLoc + "#---#" + rubyVer + "#---#" + rubyVer);

          exit(0);
        }
      }
    }
  }
}

foreach key(key_list) {
  if(registry_key_exists(key:key)) {
    foreach item (registry_enum_keys(key:key)) {
      rubyName = registry_get_sz(key:key + item, item:"DisplayName");
      if("Ruby" >< rubyName) {
        rubyVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        rubyLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!isnull(rubyVer)) {
          concl = rubyVer;
          rubyVer = ereg_replace(pattern:"-", string:rubyVer, replace:".");
          rubyVer = ereg_replace(pattern:"p", string:rubyVer, replace:"");
          set_kb_item(name:"ruby/detected", value:TRUE);
          set_kb_item(name:"ruby/smb-login/detected", value:TRUE);
          set_kb_item(name:"ruby/smb-login/port", value:port);
          set_kb_item(name:"ruby/smb-login/" + port + "/install", value:"0#---#" + rubyLoc + "#---#" + rubyVer + "#---#" + concl);

          exit(0);
        }
      }
    }
  }
}

exit(0);
