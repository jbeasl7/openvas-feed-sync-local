# SPDX-FileCopyrightText: 2001 James W. Abendschan <jwa@jammed.com>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# oracle_tnslsnr_security.nasl - NASL script to do a TNS STATUS
# command against the Oracle tnslsnr and grep out "SECURITY=OFF"

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10660");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle tnslsnr security");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2001 James W. Abendschan <jwa@jammed.com>");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_require_ports("Services/oracle_tnslsnr", 1521);
  script_mandatory_keys("oracle/database/tnslsnr/detected");

  script_tag(name:"summary", value:"The remote Oracle tnslsnr has no password assigned.");

  script_tag(name:"impact", value:"An attacker may use this fact to shut it down arbitrarily,
  thus preventing legitimate users from using it properly.");

  script_tag(name:"solution", value:"use the lsnrctrl SET PASSWORD command to assign a password to, the tnslsnr.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("port_service_func.inc");

function tnscmd(sock, command)
{
  command_length = strlen(command);
  packet_length = command_length + 58;

  # packet length - bytes 1 and 2

  plen_h = packet_length / 256;
  plen_l = 256 * plen_h;      # bah, no ( ) ?
  plen_l = packet_length - plen_h;

  clen_h = command_length / 256;
  clen_l = 256 * clen_h;
  clen_l = command_length - clen_l;

  packet = raw_string(
    plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
    0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
    clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, command
    );

  send (socket:sock, data:packet);
  r = recv(socket:sock, length:8192, timeout:5);

  return (r);
}

function oracle_tnslsnr_security(port)
{
  sock = open_sock_tcp(port);
  if (sock)
  {
    cmd = "(CONNECT_DATA=(COMMAND=STATUS))";
    reply = tnscmd(sock:sock, command:cmd);
    close(sock);
    if ( ! reply ) return 0;

    if ("SECURITY=OFF" >< reply)
    {
      security_message(port:port);
    }
    else
    {
      if ("SECURITY=ON" >< reply)
      {
        # FYI
        report = string
        (
        "This host is running a passworded Oracle tnslsnr.\n"
        );
        log_message(port:port, data:report);
      }
    }
  }
}

port = service_get_port( default:1521, proto:"oracle_tnslsnr" );
oracle_tnslsnr_security(port:port);
