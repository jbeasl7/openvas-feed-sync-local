# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117687");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-09-20 09:40:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-11-23 10:58:59 +0000 (Tue, 23 Nov 2021)");

  script_name("Weak Host Key Algorithm(s) (SSH)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_dependencies("gb_ssh_algos.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/algos_available");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc8332");
  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc8709");
  # nb: The link below is only showing some "basic" info around this topic but is included as an
  # additional reference.
  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc4253#section-6.6");

  script_tag(name:"summary", value:"The remote SSH server is configured to allow / support weak host
  key algorithm(s).");

  script_tag(name:"vuldetect", value:"Checks the supported host key algorithms of the remote SSH
  server.

  Currently weak host key algorithms are defined as the following:

  - ssh-dss: Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)");

  script_tag(name:"solution", value:"Disable the reported weak host key algorithm(s).");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = ssh_get_port( default:22 );

weak_host_key_algos = make_array( "ssh-dss", "Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)" );

if( ! supported_host_key_algos = get_kb_list( "ssh/" + port + "/server_host_key_algorithms" ) )
  exit( 0 );

found_weak_host_key_algo = FALSE;
weak_host_key_algos_report = make_array();

foreach weak_host_key_algo( keys( weak_host_key_algos ) ) {
  if( in_array( search:weak_host_key_algo, array:supported_host_key_algos, part_match:FALSE ) ) {
    weak_host_key_algos_report[weak_host_key_algo] = weak_host_key_algos[weak_host_key_algo];
    found_weak_host_key_algo = TRUE;
  }
}

if( found_weak_host_key_algo ) {

  # nb:
  # - Store the reference from this one to gb_ssh_algos.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.105565" ); # gb_ssh_algos.nasl
  register_host_detail( name:"detected_at", value:port + "/tcp" );

  report = '\n\n' + text_format_table( array:weak_host_key_algos_report, sep:" | ", columnheader:make_list( "host key algorithm", "Description" ) );
  security_message( port:port, data:"The remote SSH server supports the following weak host key algorithm(s):" + report );
  exit( 0 );
}

exit( 99 );
