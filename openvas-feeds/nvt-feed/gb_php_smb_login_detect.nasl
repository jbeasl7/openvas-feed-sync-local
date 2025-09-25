# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902435");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("PHP Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "win/lsc/search_portable_apps");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login and Powershell file search based detection of PHP.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("list_array_func.inc");
include("smb_nt.inc");
include("host_details.inc");
include("powershell_func.inc");

if (wmi_is_file_search_disabled() || is_win_cmd_exec_disabled())
  exit(0);

fileList = powershell_file_search_version(file_name_pattern: "php.exe");

if (!fileList)
  exit(0);

port = kb_smb_transport();

foreach info(split(fileList)) {
  info_comp = split(info, sep: ";", keep: FALSE);
  # powershell_file_search_version returns the .exe filename so we're stripping it away
  location = info_comp[0] - "\php.exe";

  version = info_comp[1];

  set_kb_item(name: "php/detected", value: TRUE);
  concluded = "Fileversion: " + version + " fetched from " + info_comp[0];

  set_kb_item(name:"php/detected", value: TRUE);
  set_kb_item(name:"php/smb-login/detected", value: TRUE);
  set_kb_item(name: "php/smb-login/port", value: port);
  set_kb_item(name: "php/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + concluded);
}

exit(0);
