# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108205");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-08-09 13:47:59 +0200 (Wed, 09 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for access via WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows");
  script_dependencies("toolcheck.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Tools/Present/wmi", "SMB/password", "SMB/login");
  script_exclude_keys("SMB/samba");

  script_tag(name:"summary", value:"This routine checks if an access to the remote host with the Windows Management Instrumentation (WMI)
  method is possible by using the provided SMB login/password credentials.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");

if( kb_smb_is_samba() ) exit( 0 );

host    = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();
if( ! host || ! usrname || ! passwd ) exit( 0 );

# The user hasn't filled out a login so no need
# to check if WMI access is possible.
if( ! strlen( usrname ) > 0 ) exit( 0 );

domain = kb_smb_domain();
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

wmi_close( wmi_handle:handle );

set_kb_item( name:"WMI/access_successful", value:TRUE );
set_kb_item( name:"SMB_or_WMI/access_successful", value:TRUE );

exit( 0 );
