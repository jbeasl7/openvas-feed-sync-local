# SPDX-FileCopyrightText: 2005 David Lodge
# SPDX-FileCopyrightText: New / improved code and detection since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10884");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Network Time Protocol (NTP) / NTPd / NTPsec Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Lodge");
  script_family("Product detection");
  script_require_udp_ports("Services/udp/ntp", 123);

  script_xref(name:"URL", value:"https://www.eecis.udel.edu/~mills/ntp/html/ntpd.html");
  script_xref(name:"URL", value:"https://www.ntp.org/");
  script_xref(name:"URL", value:"https://www.ntpsec.org/");

  script_tag(name:"summary", value:"UDP based detection of services supporting the Network Time
  Protocol (NTP). In addition to the protocol itself the existence of the ntpd (NTPd) / NTPsec
  daemon is detected as well.");

  script_tag(name:"insight", value:"It is possible to determine a lot of information about the
  remote host by querying the NTP variables - these include OS descriptor, and time settings.");

  script_tag(name:"solution", value:"Quickfix: Restrict default access to ignore all info
  packets.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("dump.inc");
include("cpe.inc");

function ntp_read_list( port ) {

  local_var port;
  local_var data, soc, r, no_bin, p;

  if( ! soc = open_sock_udp( port ) )
    return NULL;

  data = raw_string( 0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00 );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( ! r )
    return NULL;

  # From https://scan.shadowserver.org/ntpversion/:
  # If you would like to test your own device to see if it supports Mode 6 queries, try the command:
  # "ntpq -c rv [IP]". If the command is successful, you will see a string of information from the
  # IP that you queried that usually starts off with something like this:
  # 'associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync, version="ntpd 4.2.6p2@1.2194-o Sun Oct 17 13:35:13 UTC 2010 (1)", processor="x86_64", system="Linux/3.2.0-0.bpo.4-amd64", leap=00'.
  # If any of the strings are included we're assuming that Mode 6 is enabled (for 2021/gb_ntp_mode6_response_check.nasl)
  no_bin = bin2string( ddata:r, noprint_replacement:"" );
  if( egrep( string:no_bin, pattern:"(associd|status|version|processor|system|leap)=.+", icase:TRUE ) ) {
    set_kb_item( name:"ntp/mode6/response/received", value:TRUE );
    set_kb_item( name:"ntp/mode6/response/" + port + "/received", value:TRUE );
    set_kb_item( name:"ntp/mode6/response/" + port + "/sent_data_len", value:strlen( data ) );
    set_kb_item( name:"ntp/mode6/response/" + port + "/recv_data_len", value:strlen( r ) );
  }

  p = strstr( r, "version=" );
  if( ! p )
    p = strstr( r, "processor=" );

  if( ! p )
    p = strstr( r, "system=" );

  p = ereg_replace( string:p, pattern:raw_string( 0x22 ), replace:"'" );

  if( p )
    return( p );

  return NULL;
}

function ntp_installed( port ) {

  local_var port;
  local_var data, soc, r;

  if( ! soc = open_sock_udp( port ) )
    return NULL;

  data = raw_string( 0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA, 0x00, 0x00 );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( strlen( r ) > 10 )
    return( r );

  return NULL;
}

port = service_get_port( default:123, ipproto:"udp", proto:"ntp" );

r = ntp_installed( port:port );

if( r ) {

  # nb:
  # - Store link between this and e.g. gb_ntp_mode6_response_check.nasl
  # - We don't use the host_details.inc functions in both so we need to call this directly
  register_host_detail( name:"detected_at", value:port + "/udp" );

  set_kb_item( name:"ntp/remote/detected", value:TRUE );
  set_kb_item( name:"ntp/detected", value:TRUE );

  service_register( port:port, proto:"ntp", ipproto:"udp" );

  list = ntp_read_list( port:port );
  list = chomp( list );

  if( ! list ) {
    log_message( port:port, protocol:"udp" );
  } else {

    set_kb_item( name:"ntp/" + port + "/full_banner", value:list );
    set_kb_item( name:"ntp/full_banner/available", value:TRUE );

    if( "system=" >< list ) {

      system_line = egrep( pattern:"system=", string:list );
      os = ereg_replace( string:system_line, pattern:".*system='?([^',]+)[',].*", replace:"\1" );

      set_kb_item( name:"ntp/system_banner/available", value:TRUE );
      set_kb_item( name:"ntp/" + port + "/system_banner", value:os );
    }

    if( "processor=" >< list ) {

      processor_line = egrep( pattern:"processor=", string:list );
      processor = ereg_replace( string:processor_line, pattern:".*processor='?([^',]+)[',].*", replace:"\1" );

      set_kb_item( name:"Host/processor/ntp", value:processor );
      set_kb_item( name:"ntp/processor_banner/available", value:TRUE );
      set_kb_item( name:"ntp/" + port + "/processor_banner", value:processor );

      register_host_detail( name:"cpuinfo", value:processor, desc:"NTP(d) Server Detection" );
    }

    if( "version=" >< list ) {

      version_line = eregmatch( pattern:"version='([^']+)',", string:list );
      if( ! isnull( version_line[1] ) ) {
        set_kb_item( name:"ntp/version_banner/available", value:TRUE );
        set_kb_item( name:"ntp/" + port + "/version_banner", value:version_line[1] );
      }
    }

    # ntpd ntpsec-1.2.2,
    # ntpd ntpsec-1.1.3 2019-03-08T23:46:25Z
    # ntpd ntpsec-1.1.3 2019-11-18T06:04:00Z
    # ntpd ntpsec-1.1.0+419 2018-03-14T12:03:57-0700
    # ntpd ntpsec-1.1.8 2020-01-25T04:37:38Z
    if( version_line[1] && "ntpd ntpsec" >< version_line[1] ) {

      set_kb_item( name:"ntpsec/ntp/detected", value:TRUE );
      set_kb_item( name:"ntpsec/detected", value:TRUE );

      install = port + "/udp";
      version = "unknown";

      # nb: There was a single "1.2.2a" version
      vers = eregmatch( pattern:"ntpd ntpsec-([0-9.a]+)", string:list );
      if( ! isnull( vers[1] ) )
        version = vers[1];

      cpe = build_cpe( value:version, exp:"^([0-9.a]+)", base:"cpe:/a:ntpsec:ntpsec:" );
      if( ! cpe )
        cpe = "cpe:/a:ntpsec:ntpsec";

      register_product( cpe:cpe, location:install, port:port, service:"ntp", proto:"udp" );

      report = build_detection_report( app:"NTPsec",
                                       version:version,
                                       install:install,
                                       cpe:cpe,
                                       concluded:vers[0] );
    }

    else if( "ntpd" >< list ) {

      set_kb_item( name:"ntpd/remote/detected", value:TRUE );
      set_kb_item( name:"ntpd/detected", value:TRUE );

      install = port + "/udp";
      version = "unknown";
      CPE = "cpe:/a:ntp:ntp";

      # ntpd 4.1.1a@1.791 Wed Feb  5 17:54:41 PST 2003 (42)
      # ntpd 4.2.4p0@1.1472 Thu Sep  9 05:32:12 UTC 2010 (1)
      # ntpd 4.2.6p5@1.2349-o Mon May 19 11:25:49 UTC 2014 (1)
      # ntpd 4.2.0-a Wed Apr 10 19:15:06  2019 (1)
      # ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)
      # ntpd 4.2.8p9@1.3265-o Tue Apr 25 02:46:00 UTC 2017 (2)
      vers = eregmatch( pattern:".*ntpd ([0-9.]+)([a-z][0-9]*)?-?((RC|beta)[0-9]+)?", string:list );
      if( ! isnull( vers[1] ) ) {
        if( vers[2] =~ "[a-z][0-9]+" && vers[3] =~ "(RC|beta)" ) {
          version = vers[1] + vers[2] + " " + vers[3];
          CPE += ":" + vers[1] + ":" + vers[2] + "-" + vers[3];
        } else if( vers[2] =~ "[a-z][0-9]*" ) {
          version = vers[1] + vers[2];
          CPE += ":" + vers[1] + ":" + vers[2];
        } else {
          version = vers[1];
          CPE += ":" + vers[1];
        }
      }

      if( version && version != "unknown" ) {

        CPE = tolower( CPE );
        set_kb_item( name:"ntpd/version/detected", value:TRUE );
        set_kb_item( name:"ntpd/version", value:version );
        set_kb_item( name:"ntpd/" + port + "/version", value:version );

        set_kb_item( name:"ntpd/remote/version/detected", value:TRUE );
        set_kb_item( name:"ntpd/remote/version", value:version );
        set_kb_item( name:"ntpd/remote/" + port + "/version", value:version );
      }

      register_product( cpe:CPE, location:install, port:port, service:"ntp", proto:"udp" );

      report = build_detection_report( app:"NTPd",
                                       version:version,
                                       install:install,
                                       cpe:CPE,
                                       concluded:vers[0] );
    }

    if( report )
      report += '\n\n';

    # nb: Clean up the "list" content from any dynamic data to avoid changes in delta reports due to
    # incremental variables and similar which would show differences between two scans.
    #
    # Usually the following includes "dynamic" data we want to get rid of:
    #
    # clock=0xE96CCC8D.2D422BB6
    # clock=0xe96cd00d.e9fc1bf5
    # rootdisp=2.927
    # rootdispersion=44.657
    # sys_jitter=0.266812
    # rootdelay=0.819
    # reftime=0xe96cd02e.e91e9f90
    # offset=-0.007583
    # frequency=6.820
    # clk_jitter=0.014
    # clk_wander=0.019
    # jitter=4.583
    # peer=23725
    # peer=3328
    #
    # those are not changing that often but are still dynamic:
    #
    # expire=202412280000
    # precision=-24
    # refid=<redacted>
    #
    list = ereg_replace( string:list, pattern:"(clock|rootdisp|sys_jitter|rootdelay|reftime|offset|frequency|clk_jitter|clk_wander|rootdispersion|jitter|peer|expire|precision|refid)=([^,]+),",  replace:"\1=***replaced***," );

    # nb: Some times the "list" ends with trailing \x00 so just replace them
    list = ereg_replace( string:list, pattern:"(\\x00)+$",  replace:"" );
    list = chomp( list );

    report += 'It was possible to gather the following information from the remote NTP host:\n\n' + list;
    report += '\n\nNote: Dynamic data might have been replaced in the reporting to prevent changes in delta reports.';
    log_message( port:port, proto:"udp", data:report );
    exit( 0 );
  }
}

exit( 0 );
