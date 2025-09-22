# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108308");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of NETGEAR ProSAFE devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
url1 = "/";
url2 = "/login.htm";
url3 = "/login_new.asp";
buf  = http_get_cache( item:url1, port:port );
buf2 = http_get_cache( item:url2, port:port );
buf3 = http_get_cache( item:url3, port:port );

# nb: Note that NETGEAR has switched the writing of their name and brandings between the years,
# which changed between firmwares of e.g. the same device
# GS108Ev3 with different firmware (examples of 2.06.03 and earlier):
#
#<title>NETGEAR ProSAFE Plus Switch</title>
#<title>Netgear Prosafe Plus Switch</title>
#<div class="switchInfo">GS108Ev3 - 8-Port Gigabit ProSAFE Plus Switch</div>
#
# which changed on e.g. GS108Ev3 2.06.08 again:
#
#<title>NETGEAR GS108Ev3</title>
#<div class="switchInfo">GS108Ev3 - 8-Port Gigabit Ethernet Smart Managed Plus Switch</div>
#
# Other variants of different devices:
#
#<TITLE>NetGear GSM7224V2</TITLE> <!-- Netgear Page Title    -->
#<TITLE>NETGEAR GSM7224V2</TITLE> <!-- Netgear Page Title    -->
#<title>NetGear GS108TV1</title>
#
#<TITLE>Netgear System Login</TITLE>
#<IMG SRC = "/base/images/netgear_gsm7224_banner.gif" ALIGN="CENTER">
#

if( "<title>NETGEAR ProSAFE" >< buf ||
    "<title>Netgear Prosafe" >< buf ||
    egrep( string:buf, pattern:'<div class="switchInfo">.*ProSAFE.*</div>', icase:FALSE ) ||
    ( egrep( pattern:"<title>netgear", string:buf, icase:TRUE ) &&
      ( "/base/images/netgear_" >< buf || "/base/netgear_login.html" >< buf ||
        buf =~ "<td>Copyright &copy; .* Netgear &reg;</td>" || "login.cgi" >< buf )
    ) ||
    ( "<title>Netgear ProSAFE" >< buf2 || "<title>Netgear Prosafe" >< buf2 ) ||
    ( "ProSAFE" >< buf3 && "<TITLE>NETGEAR" >< buf3 )
  ) {

  model      = "unknown";
  fw_version = "unknown";
  fw_build   = "unknown";

  mod = eregmatch( pattern:'<div class="switchInfo">([0-9a-zA-Z\\-]+)[^\r\n]+</div>', string:buf, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
    set_kb_item( name:"netgear/prosafe/http/" + port + "/concludedUrl",
                 value:http_report_vuln_url( port:port, url:url1, url_only:TRUE ) );
  } else {
    mod = eregmatch( pattern:"/base/images/netgear_([0-9a-zA-Z\\-]+)_banner\.gif", string:buf, icase:TRUE );
    if( mod[1] ) {
      model = mod[1];
      set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
      set_kb_item( name:"netgear/prosafe/http/" + port + "/concludedUrl",
                   value:http_report_vuln_url( port:port, url:url1, url_only:TRUE ) );
    } else {
      mod = eregmatch( pattern:"<TITLE>NetGear ([0-9a-zA-Z\\-]+)</TITLE>", string:buf, icase:TRUE );
      if( mod[1] ) {
        model = mod[1];
        set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
        set_kb_item( name:"netgear/prosafe/http/" + port + "/concludedUrl",
                    value:http_report_vuln_url( port:port, url:url1, url_only:TRUE ) );
      } else {
        # var sysGeneInfor = 'JGS516PE??14:59:c0:46:a5:67?2.6.0.22?Enable?207.183.177.60?255.255.254.0?207.183.176.1?3KJ8895N00040';
        mod = eregmatch( pattern:"sysGeneInfor = '([^?]+)[^']+", string:buf2 );
        if( mod[1] ) {
          model = mod[1];
          set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
          set_kb_item( name:"netgear/prosafe/http/" + port + "/concludedUrl",
                       value:http_report_vuln_url( port:port, url:url2, url_only:TRUE ) );

          sysinfo = split( mod[0], sep:"?", keep:FALSE );
          if( ! isnull( sysinfo[3] ) )
            fw_version = sysinfo[3];

          if( ! isnull( sysinfo[2] ) ) {
            register_host_detail( name:"MAC", value:tolower( sysinfo[2] ), desc:"NETGEAR ProSAFE Devices Detection (HTTP)" );
            replace_kb_item( name:"Host/mac_address", value:tolower( sysinfo[2] ) );
          }
        } else {
          # <label class="productName">
          #  GS724TPv2 ProSAFE 24-Port Gigabit Smart Managed Switch with PoE+ and 2 SFP Ports
          mod = eregmatch( pattern:'"productName">[^A-Z]+([^ ]+)[^\r\n]+', string:buf3 );
          if( mod[1] ) {
            model = mod[1];
            set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
            set_kb_item( name:"netgear/prosafe/http/" + port + "/concludedUrl",
                         value:http_report_vuln_url( port:port, url:url3, url_only:TRUE ) );
          }
        }
      }
    }
  }

  set_kb_item( name:"netgear/prosafe/http/" + port + "/model", value:model );
  set_kb_item( name:"netgear/prosafe/http/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"netgear/prosafe/http/" + port + "/fw_build", value:fw_build );
  set_kb_item( name:"netgear/prosafe/http/detected", value:TRUE );
  set_kb_item( name:"netgear/prosafe/http/port", value:port );
  set_kb_item( name:"netgear/prosafe/detected", value:TRUE );
}

exit( 0 );
