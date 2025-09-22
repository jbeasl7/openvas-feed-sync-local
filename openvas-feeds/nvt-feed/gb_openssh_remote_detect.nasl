# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108576");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)");
  script_name("OpenSSH Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/openssh/detected");

  script_tag(name:"summary", value:"SSH banner-based detection of OpenSSH.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );

# SSH-2.0-OpenSSH_7.1-hpn14v5 FreeBSD-openssh-portable-7.1.p1_1,1
# SSH-2.0-OpenSSH
# SSH-2.0-OpenSSH_7.6 FreeBSD-openssh-portable-7.6.p1_3,1
# SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
# SSH-2.0-OpenSSH_6.4
# SSH-2.0-OpenSSH_for_Windows_7.9
# SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
# SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7
# SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3
# SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4
if( banner && "OpenSSH" >< banner ) {

  set_kb_item( name:"openssh/detected", value:TRUE );

  install   = port + "/tcp";
  version   = "unknown";
  concluded = banner;

  vers = eregmatch( pattern:"SSH.+OpenSSH[_ ](for_Windows_)?([.a-zA-Z0-9]+)[- ]?.*", string:banner );
  if( vers[2] ) {
    version   = vers[2];
    concluded = vers[0];
  }

  set_kb_item( name:"openssh/ssh/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#Server" );
  set_kb_item( name:"openssh/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh/detected", value:TRUE );
  set_kb_item( name:"openssh/ssh/port", value:port );
}

exit( 0 );
