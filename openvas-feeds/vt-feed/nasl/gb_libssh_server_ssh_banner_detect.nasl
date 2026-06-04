# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108472");
  script_version("2026-06-03T07:18:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-06-03 07:18:10 +0000 (Wed, 03 Jun 2026)");
  script_tag(name:"creation_date", value:"2018-10-17 08:43:06 +0200 (Wed, 17 Oct 2018)");
  script_name("libssh SSH Server Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/libssh/detected");

  script_xref(name:"URL", value:"https://www.libssh.org");

  script_tag(name:"summary", value:"SSH banner-based detection of a SSH server using libssh.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );

# SSH-2.0-libssh_0.8.4
# SSH-2.0-libssh-0.7.0
# SSH-2.0-libssh
# SSH-2.0-libssh-0.2
#
# nb: This seems to be a "development" version as the git
# master has always something like 0.7.90 or 0.8.90.
# SSH-2.0-libssh_0.7.90
if( banner && banner =~ "^SSH-.*libssh" ) {

  version = "unknown";
  vers = eregmatch( pattern:"^SSH-.*libssh[_-]([0-9.]+)", string:banner );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"libssh/server/detected", value:TRUE );
  set_kb_item( name:"libssh/server/ssh-banner/detected", value:TRUE );

  register_and_report_cpe( app:"libssh Server", ver:version, concluded:banner, base:"cpe:/a:libssh:libssh:", expr:"^([0-9.]+)", regPort:port, insloc:port + "/tcp" );
}

exit( 0 );
