# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105610");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-04-19 11:49:32 +0200 (Tue, 19 Apr 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"2.6");
  script_name("Weak MAC Algorithm(s) Supported (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc6668");
  # nb: The link below is only showing some "basic" info around this topic but is included as an
  # additional reference.
  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc4253#section-6.4");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow / support weak MAC
  algorithm(s).");

  script_tag(name:"vuldetect", value:"Checks the supported MAC algorithms (client-to-server and
  server-to-client) of the remote SSH server.

  Currently weak MAC algorithms are defined as the following:

  - MD5 based algorithms

  - 96-bit based algorithms

  - 64-bit based algorithms

  - 'none' algorithm");

  script_tag(name:"solution", value:"Disable the reported weak MAC algorithm(s).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

function check_algo( port, type ) {

  local_var port, type;
  local_var algos, macs, found_algo;

  if( ! type || ! port )
    return;

  algos = get_kb_list( "ssh/" + port + "/mac_algorithms_" + type );
  if( ! algos )
    return;

  macs = "";

  # Sort to not report changes on delta reports if just the order is different
  algos = sort( algos );

  foreach found_algo( algos ) {
    # nb: This should catch e.g. the following (additional examples can be seen in rfc4253):
    #
    # umac-64@openssh.com
    # umac-64-etm@openssh.com
    # hmac-md5
    # hmac-md5-96
    if( "none" >< found_algo || "md5" >< found_algo || "-96" >< found_algo || "-64" >< found_algo )
      macs += found_algo + '\n';
  }

  if( strlen( macs ) > 0 )
    return macs;
}

port = ssh_get_port( default:22 );

if( rep = check_algo( port:port, type:"client_to_server" ) )
  report = 'The remote SSH server supports the following weak client-to-server MAC algorithm(s):\n\n' + rep + '\n\n';

if( rep = check_algo( port:port, type:"server_to_client" ) )
  report += 'The remote SSH server supports the following weak server-to-client MAC algorithm(s):\n\n' + rep;

if( report ) {

  # nb:
  # - Store the reference from this one to gb_ssh_algos.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.105565" ); # gb_ssh_algos.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
