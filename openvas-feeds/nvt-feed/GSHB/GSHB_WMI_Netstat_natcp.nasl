# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94251");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-09-08 13:12:52 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Get Windows TCP Netstat over win_cmd_exec");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl", "lsc_options.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB", "SMB/password", "SMB/login");
  script_require_ports(139, 445);
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"Get Windows TCP Netstat over win_cmd_exec");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("win_cmd_func.inc");

if( kb_smb_is_samba() ) exit( 0 );
if( ! defined_func("win_cmd_exec") ) exit( 0 );

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
passwd = kb_smb_password();
if (domain){
  usrname = domain + '/' + usrname;
}

if(!host || !usrname || !passwd){
  set_kb_item(name:"GSHB/WMI/NETSTAT/log", value:"nocred");
  exit(0);
}

if(get_kb_item("win/lsc/disable_win_cmd_exec")){
  set_kb_item(name:"GSHB/WMI/NETSTAT/log", value:"win_cmd_exec manually disabled");
  exit(0);
}

a = "netstat.exe -na -p tcp";
b = "netstat.exe -na -p tcpv6";
vala = win_run_cmd (cmd:a);
valb = win_run_cmd (cmd:b);

report = vala + "\n" + valb;

set_kb_item(name:"GSHB/WMI/NETSTAT", value:report);
exit(0);
