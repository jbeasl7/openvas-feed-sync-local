# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900479");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_name("PostgreSQL Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login-based detection of PostgreSQL.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(is_win_cmd_exec_disabled())
  exit(0);

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\PostgreSQL Global Development Group\PostgreSQL\");
}

else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\PostgreSQL Global Development Group\PostgreSQL\",
                       "SOFTWARE\Wow6432Node\PostgreSQL Global Development Group\PostgreSQL\");
}

if(isnull(key_list))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\PostgreSQL")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\PostgreSQL")) {
    exit(0);
  }
}

port = kb_smb_transport();

foreach key(key_list) {

  insloc = registry_get_sz(key:key, item:"Location");
  if(insloc) {
    sysPath = insloc + "\bin";
    vers = powershell_fetch_product_version(sysPath:sysPath, file_name:"postgres.exe");
  } else {
    continue;
  }

  if(!isnull(vers)) {
    found = TRUE;
    set_kb_item(name:"postgresql/smb-login/" + port + "/installs", value:"0#---#" + insloc + "#---#" + vers + "#---#" + vers + "#---#" + os_arch);
  }
}

if(found) {
  set_kb_item(name:"postgresql/detected", value:TRUE);
  set_kb_item(name:"postgresql/smb-login/detected", value:TRUE);
  set_kb_item(name:"postgresql/smb-login/port", value:port);
}

exit(0);
