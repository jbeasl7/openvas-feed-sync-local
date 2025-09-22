# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140170");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-02-21 11:53:19 +0100 (Tue, 21 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Banner Evaluation");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script gets the HTTP banner and stores some values in the
  KB related to it.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

function set_mandatory_key( key, regex, banner, main_page_res, extra_key, extra_keys ) {

  local_var key, regex, banner, main_page_res, extra_key, extra_keys;

  if( ! key ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#key#-#set_mandatory_key" );
    return;
  }

  if( ! regex ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#regex#-#set_mandatory_key" );
    return;
  }

  if( ! banner && ! main_page_res ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#banner and main_page_res#-#set_mandatory_key" );
    return;
  }

  if( ( banner && egrep( pattern:regex, string:banner, icase:TRUE ) ) ||
      ( main_page_res && egrep( pattern:regex, string:main_page_res, icase:TRUE ) )
    ) {
    set_kb_item( name:key + "/banner", value:TRUE );

    if( extra_key )
      set_kb_item( name:extra_key, value:TRUE );

    if( extra_keys ) {
      foreach extra_key( extra_keys ) {
        set_kb_item( name:extra_key, value:TRUE );
      }
    }
  }
  return;
}

# nb: ignore_broken:TRUE is used here because no404.nasl might have set the remote host as "broken"
# due to the existence of a specific banner like "DAAP-Server" so that no web app scanning is done.
# But in this specific VT we still want to work with a possible existing banner so we're ignoring
# this information.
port = http_get_port( default:80, ignore_broken:TRUE );

if( ! banner = http_get_remote_headers( port:port, ignore_broken:TRUE ) )
  exit( 0 );

main_page_res = http_get_cache( item:"/", port:port );
# nb: Please keep this list sorted. This can be done by e.g. save the following into a file, then run:
# "cat myfile | LC_COLLATE=C sort | uniq > sorted"
# and copy the content of the "sorted" file back below.
set_mandatory_key( key:"+WN", regex:"^Server\s*:\s*+WN", banner:banner );
set_mandatory_key( key:"3S_WebServer", regex:"^Server\s*:\s*3S_WebServer", banner:banner );
set_mandatory_key( key:"4D_WebSTAR", regex:"^Server\s*:\s*4D_WebSTAR", banner:banner );
set_mandatory_key( key:"AAS", regex:"^Server\s*:\s*AAS", banner:banner );
set_mandatory_key( key:"ABwww", regex:"^Server\s*:\s*A-B WWW", banner:banner );
set_mandatory_key( key:"ACS", regex:"^Server\s*:\s*ACS", banner:banner );
set_mandatory_key( key:"ADSL_MODEM", regex:'Basic realm="ADSL Modem"', banner:banner );
set_mandatory_key( key:"ALLPLAYER-DLNA", regex:"^Server\s*:\s*ALLPLAYER-DLNA", banner:banner );
set_mandatory_key( key:"AOLserver", regex:"AOLserver", banner:banner );
set_mandatory_key( key:"ATR-HTTP", regex:"^Server\s*:\s*ATR-HTTP-Server", banner:banner );
set_mandatory_key( key:"ATS", regex:"^(Server\s*:\s*ATS|Via\s*:.*ApacheTrafficServer)", banner:banner );
set_mandatory_key( key:"Aastra_6753i", regex:'Basic realm="Aastra 6753i"', banner:banner );
set_mandatory_key( key:"Abyss", regex:"Abyss", banner:banner );
set_mandatory_key( key:"AirLive", regex:"AirLive", banner:banner );
set_mandatory_key( key:"Allegro", regex:"Allegro", banner:banner );
set_mandatory_key( key:"AntServer", regex:"^Server\s*:\s*AntServer", banner:banner );
set_mandatory_key( key:"Anti-Web", regex:"^Server\s*:\s*Anti-Web", banner:banner );
set_mandatory_key( key:"Apache-Coyote", regex:"^Server\s*:\s*Apache-Coyote", banner:banner );
set_mandatory_key( key:"Apache_SVN", regex:"^Server\s*:\s*Apache.* SVN", banner:banner );
set_mandatory_key( key:"App-webs", regex:"^Server\s*:\s*App-webs", banner:banner );
set_mandatory_key( key:"Arcadyan", regex:"^Server\s*:\s(Arcadyan )?httpd", banner:banner );
set_mandatory_key( key:"Arrakis", regex:"^Server\s*:\s*Arrakis", banner:banner );
set_mandatory_key( key:"Aspen", regex:"^Server\s*:\s*Aspen", banner:banner );
set_mandatory_key( key:"Asterisk", regex:"^Server\s*:\s*Asterisk", banner:banner );
set_mandatory_key( key:"Atheme", regex:"^Server\s*:\s*Atheme", banner:banner );
set_mandatory_key( key:"Avtech", regex:"^Server\s*:.*Avtech", banner:banner );
set_mandatory_key( key:"AWS", regex:"^Server\s*:\s*AWS \(Ada Web Server\)", banner:banner );
set_mandatory_key( key:"BCReport", regex:"BCReport", banner:banner );
set_mandatory_key( key:"BadBlue", regex:"BadBlue", banner:banner );
set_mandatory_key( key:"BarracudaHTTP", regex:"^Server\s*:\s*BarracudaHTTP", banner:banner );
set_mandatory_key( key:"Basic_realm", regex:"^WWW-Authenticate\s*:\s*Basic realm=", banner:banner );
set_mandatory_key( key:"BigFixHTTPServer", regex:"^Server\s*:\s*BigFixHTTPServer", banner:banner );
set_mandatory_key( key:"BlueDragon", regex:"BlueDragon Server", banner:banner );
set_mandatory_key( key:"Boa", regex:"^Server\s*:\s*Boa", banner:banner );
set_mandatory_key( key:"Brickcom", regex:'www-authenticate\\s*:\\s*basic\\s+realm\\s*=\\s*"brickcom', banner:banner );
set_mandatory_key( key:"CIMPLICITY", regex:"^Server\s*:\s*CIMPLICITY", banner:banner );
set_mandatory_key( key:"Canon", regex:"^Server\s*:\s*CANON HTTP Server", banner:banner );
set_mandatory_key( key:"CarelDataServer", regex:"^Server\s*:\s*CarelDataServer", banner:banner );
set_mandatory_key( key:"Cherokee", regex:"^Server\s*:\s*Cherokee", banner:banner );
set_mandatory_key( key:"CherryPy", regex:"^Server\s*:\s*CherryPy", banner:banner );
set_mandatory_key( key:"CirCarLife", regex:"^Server\s*:\s*CirCarLife Scada", banner:banner );
set_mandatory_key( key:"Cohu", regex:"^Server\s*:\s*Cohu Camera", banner:banner );
set_mandatory_key( key:"CommuniGatePro", regex:"^Server\s*:\s*CommuniGatePro", banner:banner );
set_mandatory_key( key:"CompaqHTTPServer", regex:"^Server\s*:\s*CompaqHTTPServer", banner:banner );
set_mandatory_key( key:"Contiki-OS", regex:"^Server\s*:\s*Contiki/", banner:banner );
set_mandatory_key( key:"CouchDB", regex:"^Server\s*:\s*CouchDB", banner:banner );
set_mandatory_key( key:"Couchbase_Server", regex:"^Server\s*:\s*Couchbase Server", banner:banner );
set_mandatory_key( key:"Cross_Web_Server", regex:"^Server\s*:\s*Cross Web Server", banner:banner );

# nb:
# - As there are a huge amount of different D-Link devices those are more generic then others
# - The response check on the "main_page_res" is just included as a fallback to catch as much as
#   possible
# - While some vendor strings have been seen like ">D-LINK SYSTEMS" the set_mandatory_key() function
#   is case insensitive so no special handling had to be used here
# - Due to the usage of "^" in a few strings the ".*" had to be included in a few strings below
# - To make them a little bit more strict a trailing space had to be included in the ".*D-Link "
#   pattern
set_mandatory_key( key:"d-link/dir", regex:'^(Server\\s*:\\s*(Linux, (HTTP|WEBACCESS|STUNNEL)/1\\.[01], DIR|DIR-[0-9]+ web server|Mathopd|WebServer|lighttpd|httpd|Ubicom|nginx|Boa|jjhttpd|mini_httpd|eCos Embedded Web Server)|.*<script>window\\.location\\.href\\s*=\\s*"/cgi/ssi/login_pic\\.asp";</script>|.*(D-Link |(support|www)\\.dlink\\.com))', banner:banner, main_page_res:main_page_res );
set_mandatory_key( key:"d-link/dns", regex:"^(Server\s*:\s*(lighttpd/|GoAhead-Webs)|.*(D-Link |(support|www)\.dlink\.com))", banner:banner, main_page_res:main_page_res ); # For gb_dlink_dns_http_detect.nasl
set_mandatory_key( key:"d-link/dsl", regex:"^(Server\s*:\s*(Boa|micro_httpd|Linux,|RomPager|uhttpd)|.*(D-Link |(support|www)\.dlink\.com)|.*<title>VDSL Router<)", banner:banner, main_page_res:main_page_res ); # For gb_dlink_dsl_http_detect.nasl
set_mandatory_key( key:"d-link/dwr", regex:"^(Server\s*:\s*(GoAhead-Webs|server|Alpha_webserv|WebServer)|.*(D-Link |(support|www)\.dlink\.com))", banner:banner, main_page_res:main_page_res ); # For gb_dlink_dwr_http_detect.nasl
# WWW-Authenticate: Basic realm="DCS-2530L"
# WWW-Authenticate: Basic realm="DCS-932L_68"
# WWW-Authenticate: Digest realm="DCS-2530L"
# WWW-Authenticate: Basic realm="DCS-2103"
set_mandatory_key( key:"d-link/dcs", regex:'(Server\\s*:\\s*dcs-lig-httpd|(Basic|Digest) realm="DCS-[0-9]+|(D-Link |(support|www)\\.dlink\\.com))', banner:banner, main_page_res:main_page_res );

# nb: The "." shouldn't be escaped, see 2017/gb_netgear_cve_2016_5649.nasl for more info.
set_mandatory_key( key:"DGN2200", regex:'^WWW-Authenticate\\s*:\\s*Basic realm="NETGEAR.DGN2200', banner:banner );
set_mandatory_key( key:"DGND3700", regex:'^WWW-Authenticate\\s*:\\s*Basic realm="NETGEAR.DGND3700', banner:banner );
set_mandatory_key( key:"DHost", regex:"^Server\s*:\s*DHost.+HttpStk", banner:banner );
set_mandatory_key( key:"DSL-N55U", regex:'Basic realm="DSL-N55U', banner:banner );
set_mandatory_key( key:"DSL_Router", regex:'WWW-Authenticate\\s*:\\s*Basic realm="DSL Router"', banner:banner );
set_mandatory_key( key:"DWS", regex:"^Server\s*:\s*DWS", banner:banner );
set_mandatory_key( key:"DeWeS", regex:"^Server\s*:\s*DeWeS", banner:banner );
set_mandatory_key( key:"Diva_HTTP", regex:"^Server\s*:\s*Diva HTTP Plugin", banner:banner );
set_mandatory_key( key:"Domino", regex:"^Server\s*:.*Domino.*", banner:banner );
set_mandatory_key( key:"EA2700", regex:"EA2700", banner:banner );
set_mandatory_key( key:"EAServer", regex:"EAServer", banner:banner );
set_mandatory_key( key:"ELOG_HTTP", regex:"^Server\s*:\s*ELOG HTTP", banner:banner );
set_mandatory_key( key:"ETag", regex:"ETag\s*:", banner:banner );
set_mandatory_key( key:"EasyFileSharingWebServer", regex:"^Server\s*:\s*Easy File Sharing Web Server", banner:banner );
set_mandatory_key( key:"Easy_Chat_Server", regex:"Easy Chat Server", banner:banner );
set_mandatory_key( key:"Embedded_HTTP_Server", regex:"^Server\s*:\s*Embedded HTTP Server", banner:banner );
set_mandatory_key( key:"Embedthis-Appweb", regex:"^Server\s*:\s*Embedthis-Appweb", banner:banner );
set_mandatory_key( key:"Enhydra", regex:"Enhydra", banner:banner );
set_mandatory_key( key:"Ethernut", regex:"^Server\s*:\s*Ethernut", banner:banner );
set_mandatory_key( key:"EverFocus", regex:'realm="(EPARA|EPHD|ECOR)[^"]+"', banner:banner );
set_mandatory_key( key:"ExaGrid", regex:"^Server\s*:\s*ExaGrid", banner:banner );
set_mandatory_key( key:"FNET", regex:"^Server\s*:\s*FNET HTTP", banner:banner );
set_mandatory_key( key:"FlashCom", regex:"^Server\s*:\s*FlashCom", banner:banner );
set_mandatory_key( key:"GeoHttpServer", regex:"^Server\s*:\s*GeoHttpServer", banner:banner );
set_mandatory_key( key:"GoAhead-Webs", regex:"^Server\s*:\s*GoAhead-Webs", banner:banner );
set_mandatory_key( key:"Grandstream_GXP", regex:"^Server\s*:\s*Grandstream GXP", banner:banner );
set_mandatory_key( key:"HFS", regex:"^Server\s*:\s*HFS", banner:banner );
set_mandatory_key( key:"HHVM", regex:"^X-Powered-By\s*:\s*HHVM", banner:banner );
set_mandatory_key( key:"HTTPserv", regex:"^Server\s*:.*HTTPserv\s*:", banner:banner );
set_mandatory_key( key:"HWS", regex:"^Server\s*:\s*.*\(HWS[0-9]+\)", banner:banner );
set_mandatory_key( key:"Herberlin_Bremsserver", regex:"^Server\s*:\s*Herberlin Bremsserver", banner:banner );
set_mandatory_key( key:"Hiawatha", regex:"^Server\s*:\s*Hiawatha", banner:banner );
set_mandatory_key( key:"HomeSeer", regex:"^Server\s*:\s*HomeSeer", banner:banner );
set_mandatory_key( key:"HttpServer", regex:"^Server\s*:\s*HttpServer", banner:banner );
set_mandatory_key( key:"HyNetOS", regex:"HyNetOS", banner:banner );
set_mandatory_key( key:"IAMT", regex:"^Server\s*:\s*Intel\(R\) Active Management Technology", banner:banner );
set_mandatory_key( key:"IBM_HTTP_Server", regex:"^Server\s*:\s*IBM[_-]HTTP[-_]Server", banner:banner );
set_mandatory_key( key:"IBM_WebSphere", regex:"^Server\s*:\s*IBM WebSphere", banner:banner );
set_mandatory_key( key:"IIS", regex:"^Server\s*:\s*(Microsoft-)?IIS", banner:banner );
set_mandatory_key( key:"ILOM-Web-Server", regex:"^Server\s*:\s*(Sun|Oracle)-ILOM-Web-Server", banner:banner );
# nb: Might need some improvements / extensions in the future if this doesn't match all known IPP services
set_mandatory_key( key:"IPP", regex:"^(Server\s*:.*IPP|Server\s*:\s*HP-ChaiServer|Content-type\s*:\s*application/ipp|.+cups\.css|.+/hp/device/info_deviceStatus.html)", banner:banner, main_page_res:main_page_res, extra_key:"Host/could_support_ipp" );
set_mandatory_key( key:"IOServer", regex:"^Server\s*:\s*IOServer", banner:banner );
set_mandatory_key( key:"IQhttp", regex:"^Server\s*:\s*IQhttp", banner:banner );
set_mandatory_key( key:"ISM", regex:"^Server\s*:\s*Intel\(R\) Standard Manageability", banner:banner );
set_mandatory_key( key:"IWB", regex:"^Server\s*:\s*IWB Web-Server", banner:banner );
set_mandatory_key( key:"IceWarp", regex:"IceWarp", banner:banner );
set_mandatory_key( key:"Indy", regex:"^Server\s*:\s*Indy", banner:banner );
set_mandatory_key( key:"Ingate-SIParator", regex:"^Server\s*:\s*Ingate-SIParator", banner:banner );
set_mandatory_key( key:"InterVations", regex:"^Server\s*:.*InterVations", banner:banner );
set_mandatory_key( key:"Ipswitch", regex:"^Server\s*:\s*Ipswitch", banner:banner );
set_mandatory_key( key:"JAWSJAWS", regex:"^Server\s*:\s*JAWS", banner:banner );
set_mandatory_key( key:"JBoss-EAP", regex:"^Server\s*:\s*JBoss-EAP", banner:banner );
set_mandatory_key( key:"JDownloader", regex:'WWW-Authenticate\\s*:\\s*Basic realm="JDownloader', banner:banner );
set_mandatory_key( key:"JRun", regex:"JRun", banner:banner );
set_mandatory_key( key:"JVC_API", regex:"^Server\s*:\s*JVC.*API Server", banner:banner );
set_mandatory_key( key:"JetBrainsIDEs", regex:"^Server\s*:\s*(PyCharm|WebStorm|CLion|DataGrip|IntelliJ IDEA|JetBrains MPS|jetBrains Rider|RubyMine)", banner:banner );
set_mandatory_key( key:"Jetadmin", regex:"HP Web Jetadmin", banner:banner );
set_mandatory_key( key:"Jetty", regex:"^Server\s*:\s*Jetty", banner:banner );
set_mandatory_key( key:"Jetty_EAServer", regex:"^Server\s*:\s*Jetty\(EAServer", banner:banner );
set_mandatory_key( key:"JibbleWebServer", regex:"^Server\s*:\s*JibbleWebServer", banner:banner );
set_mandatory_key( key:"KACE-Appliance", regex:"X-(Dell)?KACE-Appliance\s*:", banner:banner );
set_mandatory_key( key:"KCEWS", regex:"^Server\s*:\s*Kerio Control Embedded Web Server", banner:banner );
set_mandatory_key( key:"KNet", regex:"^Server\s*:\s*KNet", banner:banner );
set_mandatory_key( key:"Kannel", regex:"^Server\s*:\s*Kannel", banner:banner );
set_mandatory_key( key:"Kerio_WinRoute", regex:"^Server\s*:\s*Kerio WinRoute Firewall", banner:banner );
set_mandatory_key( key:"LANCOM", regex:"^Server\s*:\s*LANCOM", banner:banner );
set_mandatory_key( key:"LPS", regex:"^Server\s*:\s*LPS", banner:banner );
set_mandatory_key( key:"LabVIEW", regex:"^Server\s*:\s*LabVIEW", banner:banner );
set_mandatory_key( key:"Light_HTTPd", regex:"Light HTTPd", banner:banner );
set_mandatory_key( key:"LilHTTP", regex:"^Server\s*:\s*LilHTTP", banner:banner );
set_mandatory_key( key:"LiteSpeed", regex:"LiteSpeed", banner:banner );
set_mandatory_key( key:"LocalWEB2000", regex:"^Server\s*:\s*.*LocalWEB2000", banner:banner );
set_mandatory_key( key:"LogitechMediaServer", regex:"^Server\s*:\s*Logitech Media Server", banner:banner );
set_mandatory_key( key:"Lotus", regex:"Lotus", banner:banner );
set_mandatory_key( key:"Loxone", regex:"^Server\s*:\s*Loxone", banner:banner );
set_mandatory_key( key:"MLDonkey", regex:"ML[Dd]onkey", banner:banner );
set_mandatory_key( key:"MPC-HC", regex:"^Server\s*:\s*MPC-HC WebServer", banner:banner );
set_mandatory_key( key:"MagnoWare", regex:"^Server\s*:\s*MagnoWare", banner:banner );
set_mandatory_key( key:"MailEnable", regex:"^Server\s*:\s*.*MailEnable", banner:banner );
set_mandatory_key( key:"Mathopd", regex:"^Server\s*:\s*Mathopd", banner:banner );
set_mandatory_key( key:"MatrixSSL", regex:"^Server\s*:\s*.*MatrixSSL", banner:banner );
set_mandatory_key( key:"Mbedthis-Appweb", regex:"^Server\s*:\s*Mbedthis-Appweb", banner:banner );
set_mandatory_key( key:"McAfee_Web_Gateway", regex:"McAfee Web Gateway", banner:banner );
set_mandatory_key( key:"Microsoft-HTTPAPI", regex:"Microsoft-HTTPAPI", banner:banner );
set_mandatory_key( key:"MiniWebSvr", regex:"MiniWebSvr", banner:banner );
set_mandatory_key( key:"Mini_web_server", regex:"^Server\s*:\s*Mini web server", banner:banner );
set_mandatory_key( key:"MobileWebServer", regex:"^Server\s*:\s*MobileWebServer", banner:banner );
set_mandatory_key( key:"MochiWeb", regex:"MochiWeb", banner:banner );
set_mandatory_key( key:"Mojolicious", regex:"^Server\s*:\s*Mojolicious", banner:banner );
set_mandatory_key( key:"Mongoose", regex:"^Server\s*:\s*Mongoose", banner:banner );
set_mandatory_key( key:"Monitorix", regex:"Monitorix", banner:banner );
set_mandatory_key( key:"Monkey", regex:"^Server\s*:\s*Monkey", banner:banner );
set_mandatory_key( key:"MoxaHttp", regex:"^Server\s*:\s*MoxaHttp", banner:banner );
set_mandatory_key( key:"MyNetN679", regex:"MyNetN[6|7|9]", banner:banner );
set_mandatory_key( key:"MyServer", regex:"MyServer ([0-9.]+)", banner:banner );
set_mandatory_key( key:"NETGEAR", regex:'Basic realm="NETGEAR', banner:banner );
# nb: The "." shouldn't be escaped, see 2017/gb_netgear_cve_2016_5649.nasl for more info.
set_mandatory_key( key:"NETGEAR_DGN", regex:'Basic realm="NETGEAR.DGN', banner:banner );
set_mandatory_key( key:"NaviCOPA", regex:"NaviCOPA", banner:banner );
set_mandatory_key( key:"Nero-MediaHome", regex:"Nero-MediaHome", banner:banner );
set_mandatory_key( key:"NetApp", regex:"^Server\s*:\s*(NetApp|Data ONTAP)", banner:banner );
set_mandatory_key( key:"NetData", regex:"NetData Embedded HTTP Server", banner:banner );
set_mandatory_key( key:"NetDecision-HTTP-Server", regex:"^Server\s*:\s*NetDecision-HTTP-Server", banner:banner );
set_mandatory_key( key:"Netscape_iPlanet", regex:"(Netscape|iPlanet)", banner:banner );
set_mandatory_key( key:"Netwave_IP_Camera", regex:"Netwave IP Camera", banner:banner );
set_mandatory_key( key:"Nimble", regex:"^Server\s*:\s*Nimble", banner:banner );
set_mandatory_key( key:"Norman_Security", regex:"^Server\s*:\s*Norman Security", banner:banner );
set_mandatory_key( key:"Novell_Netware", regex:"(Novell|Netware)", banner:banner );
set_mandatory_key( key:"Nucleus", regex:"^Server\s*:\s*Nucleus", banner:banner );
set_mandatory_key( key:"NullLogic_Groupware", regex:"NullLogic Groupware", banner:banner );
set_mandatory_key( key:"Null_httpd", regex:"^Server\s*:\s*Null httpd", banner:banner );
set_mandatory_key( key:"OmniHTTPd", regex:"^Server\s*:\s*OmniHTTPd", banner:banner );
set_mandatory_key( key:"OpenSSL", regex:"^Server\s*:.*OpenSSL", banner:banner, extra_key:"openssl_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"OpenVPN_AS", regex:"^Server\s*:\s*OpenVPN-AS", banner:banner );
set_mandatory_key( key:"Oracle", regex:"Oracle", banner:banner );
set_mandatory_key( key:"Oracle-Application-Server", regex:"Oracle[ -]Application[ -]Server", banner:banner );
set_mandatory_key( key:"Oracle-Application-or-HTTP-Server", regex:"Oracle[ -](Application|HTTP)[ -]Server", banner:banner );
set_mandatory_key( key:"OracleAS-Web-Cache", regex:"OracleAS-Web-Cache", banner:banner );
set_mandatory_key( key:"OrientDB", regex:"OrientDB Server", banner:banner );
set_mandatory_key( key:"Orion", regex:"^Server\s*:\s*Orion", banner:banner );
set_mandatory_key( key:"PHP", regex:"PHP", banner:banner );
set_mandatory_key( key:"PMSoftware-SWS", regex:"^Server\s*:\s*PMSoftware-SWS", banner:banner );
set_mandatory_key( key:"PRN2001", regex:'Basic realm="PRN2001"', banner:banner );
set_mandatory_key( key:"PRTG", regex:"^Server\s*:\s*PRTG", banner:banner );
set_mandatory_key( key:"PST10", regex:"^Server\s*:\s*PST10 WebServer", banner:banner );
set_mandatory_key( key:"PanWeb", regex:"^Server\s*:\s*PanWeb Server", banner:banner );
set_mandatory_key( key:"Perl", regex:'^Server\\s*:.* Perl(/| |$|\r\n)', banner:banner, extra_key:"perl_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"Pi3Web", regex:"Pi3Web", banner:banner );
set_mandatory_key( key:"Play_Framework", regex:"^Server\s*:\s*Play. Framework", banner:banner );
set_mandatory_key( key:"Polipo", regex:"^Server\s*:\s*Polipo", banner:banner );
set_mandatory_key( key:"Polycom_SoundPoint", regex:"^Server\s*:\s*Polycom SoundPoint IP", banner:banner );
set_mandatory_key( key:"Promotic", regex:"^Server\s*:\s*pm", banner:banner );
set_mandatory_key( key:"PsiOcppApp", regex:"^Server\s*:\s*PsiOcppApp", banner:banner );
set_mandatory_key( key:"QuickTime_Darwin", regex:"(QuickTime|DSS)", banner:banner );
set_mandatory_key( key:"RT-Device", regex:'Basic realm="RT-', banner:banner );
set_mandatory_key( key:"RT-G32", regex:'Basic realm="RT-G32"', banner:banner );
set_mandatory_key( key:"RT-N10E", regex:'Basic realm="RT-N10E"', banner:banner );
set_mandatory_key( key:"RT-N56U", regex:'Basic realm="RT-N56U"', banner:banner );
set_mandatory_key( key:"RTC", regex:"^Server\s*:\s*RTC", banner:banner );
set_mandatory_key( key:"Raid_Console", regex:'realm="Raid Console"', banner:banner );
set_mandatory_key( key:"RaidenHTTPD", regex:"^Server\s*:\s*RaidenHTTPD", banner:banner );
set_mandatory_key( key:"Rapid_Logic", regex:"^Server\s*:\s*Rapid Logic", banner:banner );
set_mandatory_key( key:"RealVNC", regex:"RealVNC", banner:banner );
set_mandatory_key( key:"RemotelyAnywhere", regex:"RemotelyAnywhere", banner:banner );
set_mandatory_key( key:"RemotelyAnywhere", regex:"^Server\s*:\s*RemotelyAnywhere", banner:banner );
set_mandatory_key( key:"Resin", regex:"^Server\s*:\s*Resin", banner:banner );
set_mandatory_key( key:"RomPager", regex:"^Server\s*:\s*RomPager", banner:banner );
set_mandatory_key( key:"Router_Webserver", regex:"^Server\s*:\s*Router Webserver", banner:banner );
set_mandatory_key( key:"Roxen", regex:"Roxen", banner:banner );
set_mandatory_key( key:"SIP-T38G", regex:'Basic realm="Gigabit Color IP Phone SIP-T38G"', banner:banner );
set_mandatory_key( key:"SMC6128L2", regex:'Basic realm="SMC6128L2', banner:banner );
set_mandatory_key( key:"SOAPpy", regex:"SOAPpy", banner:banner );
set_mandatory_key( key:"SWS", regex:"^Server\s*:\s*SWS-", banner:banner );
set_mandatory_key( key:"SaServer", regex:"^Server\s*:\s*SaServer", banner:banner );
set_mandatory_key( key:"Saia_PCD", regex:"^Server\s*:\s*Saia PCD", banner:banner );
set_mandatory_key( key:"Sami_HTTP", regex:"^Server\s*:.*Sami HTTP Server", banner:banner );
set_mandatory_key( key:"Savant", regex:"^Server\s*:\s*Savant", banner:banner );
set_mandatory_key( key:"Schneider-WEB", regex:"^Server\s*:\s*Schneider-WEB", banner:banner );
set_mandatory_key( key:"SentinelKeysServer", regex:"^Server\s*:\s*SentinelKeysServer", banner:banner );
set_mandatory_key( key:"Serv-U", regex:"^Server\s*:\s*Serv-U", banner:banner );
set_mandatory_key( key:"Serva32", regex:"^Server\s*:\s*Serva32", banner:banner );
set_mandatory_key( key:"ServersCheck_Monitoring_Server", regex:"^Server\s*:\s*ServersCheck_Monitoring_Server", banner:banner );
set_mandatory_key( key:"Shareaza", regex:"^Server\s*:\s*Shareaza", banner:banner );
set_mandatory_key( key:"SiemensGigaset-Server", regex:"^Server\s*:\s*SiemensGigaset-Server", banner:banner );
set_mandatory_key( key:"Simple-Server", regex:"^Server\s*:\s*Simple-Server", banner:banner );
set_mandatory_key( key:"SimpleServer", regex:"SimpleServer", banner:banner );
set_mandatory_key( key:"SiteScope", regex:"SiteScope", banner:banner );
set_mandatory_key( key:"SkyIPCam", regex:'Basic realm="SkyIPCam"', banner:banner );
set_mandatory_key( key:"SnIP", regex:'Basic realm="SnIP', banner:banner );
set_mandatory_key( key:"Sockso", regex:"^Server\s*:\s*Sockso", banner:banner );
set_mandatory_key( key:"SonicWALL", regex:"^Server\s*:\s*SonicWALL", banner:banner );
set_mandatory_key( key:"Sonos", regex:"Linux UPnP.*Sonos", banner:banner );
set_mandatory_key( key:"SpecView", regex:"SpecView", banner:banner );
set_mandatory_key( key:"Statistics_Server", regex:"^Server\s*:.*Statistics Server", banner:banner );
set_mandatory_key( key:"StorageGRID", regex:"^Server\s*:\s*StorageGRID", banner:banner );
set_mandatory_key( key:"Sun-Java-System-Web-Proxy-Server", regex:"^Server\s*:\s*Sun-Java-System-Web-Proxy-Server", banner:banner );
set_mandatory_key( key:"SunWWW", regex:"^Server\s*:\s*Sun-", banner:banner );
set_mandatory_key( key:"TD-W8951ND", regex:' Basic realm="TD-W8951ND"', banner:banner );
set_mandatory_key( key:"TD_Contact_Management_Server", regex:"^Server\s*:\s*TD Contact Management Server", banner:banner );
set_mandatory_key( key:"TELES_AG", regex:"^Server\s*:\s*TELES AG", banner:banner );
set_mandatory_key( key:"TOSHIBA", regex:"^Server\s*:\s*TOSHIBA", banner:banner );
set_mandatory_key( key:"TVMOBiLi", regex:"TVMOBiLi UPnP Server", banner:banner );
set_mandatory_key( key:"TVersity_Media_Server", regex:"TVersity Media Server", banner:banner );
set_mandatory_key( key:"TinyServer", regex:"^Server\s*:\s*TinyServer", banner:banner );
set_mandatory_key( key:"TinyWeb", regex:"^Server\s*:.*TinyWeb", banner:banner );
set_mandatory_key( key:"Tomcat", regex:"^Server\s*:.*Apache.* Tomcat", banner:banner );
set_mandatory_key( key:"TopCMM", regex:"^Server\s*:\s*TopCMM Server", banner:banner );
set_mandatory_key( key:"TreeNeWS", regex:"^Server\s*:\s*TreeNeWS", banner:banner );
set_mandatory_key( key:"UltiDev_Cassini", regex:"^Server\s*:\s*UltiDev Cassini", banner:banner );
set_mandatory_key( key:"Univention", regex:"Univention", banner:banner );
set_mandatory_key( key:"Unspecified-UPnP", regex:"^Server\s*:\s*Unspecified, UPnP", banner:banner );
set_mandatory_key( key:"VLC_stream", regex:'Basic realm="VLC stream"', banner:banner );
set_mandatory_key( key:"Varnish", regex:"X-Varnish", banner:banner );
set_mandatory_key( key:"VisualRoute", regex:"^Server\s*:\s*VisualRoute", banner:banner );
set_mandatory_key( key:"VxWorks", regex:"VxWorks", banner:banner );
set_mandatory_key( key:"W4E", regex:"WebServer 4 Everyone", banner:banner );
set_mandatory_key( key:"WDaemon", regex:"^Server\s*:\s*WDaemon", banner:banner );
set_mandatory_key( key:"WEBrick", regex:"^Server\s*:\s*WEBrick", banner:banner );
set_mandatory_key( key:"WNR1000", regex:"NETGEAR WNR1000", banner:banner );
set_mandatory_key( key:"WNR1000v3", regex:"NETGEAR WNR1000v3", banner:banner );
set_mandatory_key( key:"WR841N", regex:"WR841N", banner:banner );
set_mandatory_key( key:"WRT54G", regex:'realm="WRT54G"', banner:banner );
set_mandatory_key( key:"WSO2_Carbon", regex:"^Server\s*:\s*WSO2 Carbon Server", banner:banner );
set_mandatory_key( key:"WSO2_SOA", regex:"^Server\s*:\s*WSO2 SOA Enablement Server", banner:banner );
set_mandatory_key( key:"WebBox", regex:"^Server\s*:\s*WebBox", banner:banner );
set_mandatory_key( key:"WebLogic", regex:"^Server\s*:.*WebLogic", banner:banner );
set_mandatory_key( key:"WebServer_IPCamera_Logo", regex:"^Server\s*:\s*WebServer\(IPCamera_Logo\)", banner:banner );
set_mandatory_key( key:"Web_Server", regex:"^Server\s*:\s*Web Server", banner:banner );
set_mandatory_key( key:"Web_Server_4D", regex:"Web_Server_4D", banner:banner );
set_mandatory_key( key:"Weborf", regex:"^Server\s*:\s*[Ww]eborf", banner:banner );
set_mandatory_key( key:"WildFly", regex:"^Server\s*:\s*WildFly", banner:banner );
set_mandatory_key( key:"WinGate", regex:"WinGate", banner:banner );
set_mandatory_key( key:"WindRiver-WebServer", regex:"WindRiver-WebServer", banner:banner );
set_mandatory_key( key:"Wing_FTP/Server", regex:"^Server\s*:\s*Wing FTP Server", banner:banner );
set_mandatory_key( key:"X-Kazaa-Username", regex:"X-Kazaa-Username", banner:banner );
set_mandatory_key( key:"X-Mag", regex:"^X-Mag\s*:", banner:banner );
set_mandatory_key( key:"Xeneo", regex:"Xeneo", banner:banner );
set_mandatory_key( key:"Xerver", regex:"^Server\s*:\s*Xerver", banner:banner );
set_mandatory_key( key:"Xitami", regex:"^Server\s*:\s*Xitami", banner:banner );
set_mandatory_key( key:"Yaws", regex:"^Server\s*:\s*Yaws", banner:banner );
set_mandatory_key( key:"Z-World_Rabbit", regex:"^Server\s*:\s*Z-World Rabbit", banner:banner );
set_mandatory_key( key:"ZK_Web_Server", regex:"^Server\s*:\s*ZK Web Server", banner:banner );
set_mandatory_key( key:"ZXV10_W300", regex:'Basic realm="ZXV10 W300"', banner:banner );
set_mandatory_key( key:"ZendServer", regex:"ZendServer", banner:banner );
set_mandatory_key( key:"Zervit", regex:"^Server\s*:\s*Zervit", banner:banner );
set_mandatory_key( key:"Zeus", regex:"^Server\s*:\s*Zeus", banner:banner );
set_mandatory_key( key:"ZyXEL-RomPager", regex:"ZyXEL-RomPager", banner:banner );
set_mandatory_key( key:"multi/ip_cameras", regex:'(alt="ABUS Security-Center"|<title>IP CAMERA Viewer</title>)', banner:banner, main_page_res:main_page_res );
set_mandatory_key( key:"adobe/jrun", regex:"(^[Ss]erver\s*:\s*JRun Web Server|<title>JRun Servlet Error</title>)", banner:banner, main_page_res:main_page_res );
set_mandatory_key( key:"agent_dvr", regex:'^[Ww]{3}-[Aa]uthenticate\\s*:\\s*Basic realm="Agent DVR"', banner:banner );
set_mandatory_key( key:"aiohttp", regex:"^Server\s*:.*aiohttp", banner:banner );
set_mandatory_key( key:"akamai_ghost", regex:"^Server\s*:\s*AkamaiGHost", banner:banner );
set_mandatory_key( key:"akka", regex:"^Server\s*:\s*akka-http", banner:banner );
set_mandatory_key( key:"alchemy_eye", regex:"^Server\s*:\s*Alchemy Eye", banner:banner );
set_mandatory_key( key:"alibaba", regex:"^Server\s*:\s*[Aa]libaba", banner:banner );
set_mandatory_key( key:"allshare", regex:"^SERVER\s*:\s*(UPnP/[0-9]\.[0-9]\s*)?Samsung Allshare Server", banner:banner );
set_mandatory_key( key:"anweb", regex:"^Server\s*:\s*AnWeb", banner:banner );
set_mandatory_key( key:"apache/APISIX", regex:"^Server\s*:\s*APISIX", banner:banner );
set_mandatory_key( key:"apache/http_server", regex:"^Server\s*:\s(Apache(-AdvancedExtranetServer)?($|/)|Rapidsite/Apa)", banner:banner );
set_mandatory_key( key:"apache/jserv", regex:"^Server\s*:.*apachejserv", banner:banner );
set_mandatory_key( key:"appleshareip", regex:"^Server\s*:\s*AppleShareIP", banner:banner );
set_mandatory_key( key:"argosoft_mailserver", regex:"^Server\s*:\s*ArgoSoft Mail Server", banner:banner );
set_mandatory_key( key:"bitkeeper", regex:"^Server\s*:.*bkhttp", banner:banner );
set_mandatory_key( key:"bozohttpd", regex:"^Server\s*:\s*bozohttpd", banner:banner );
set_mandatory_key( key:"cassini", regex:"^Server\s*:\s*(Microsoft-)?Cassini", banner:banner );
set_mandatory_key( key:"caudium", regex:"^Server\s*:\s*Caudium", banner:banner );
set_mandatory_key( key:"cern", regex:"^Server\s*:\s*CERN", banner:banner );
set_mandatory_key( key:"circontrol/raption", regex:"^Server\s*:\s*Raption", banner:banner );
set_mandatory_key( key:"cisco/ios_http", regex:"^Server\s*:\s*cisco-IOS", banner:banner );
set_mandatory_key( key:"communique", regex:"^Server\s*:.*Communique", banner:banner );
set_mandatory_key( key:"corehttp", regex:"^Server\s*:\s*corehttp", banner:banner );
set_mandatory_key( key:"coturn", regex:"^Server\s*:\s*Coturn", banner:banner );
set_mandatory_key( key:"cougar", regex:"^Server\s*:.*Cougar.*", banner:banner );
set_mandatory_key( key:"cowboy", regex:"^Server\s*:\s*cowboy", banner:banner );
set_mandatory_key( key:"cups", regex:"^Server\s*:.*CUPS", banner:banner );
set_mandatory_key( key:"dcs-lig-httpd", regex:"^Server\s*:\s*dcs-lig-httpd", banner:banner );
set_mandatory_key( key:"debut", regex:"^Server\s*:\s*debut", banner:banner );
set_mandatory_key( key:"dwhttp", regex:"dwhttp", banner:banner );
set_mandatory_key( key:"dwhttpd", regex:"dwhttpd", banner:banner );
set_mandatory_key( key:"eMule", regex:"eMule", banner:banner );
set_mandatory_key( key:"eWON", regex:"^Server\s*:\s*eWON", banner:banner );
set_mandatory_key( key:"efmws", regex:"^Server\s*:\s*Easy File Management Web Server", banner:banner );
set_mandatory_key( key:"emweb", regex:"^Server\s*:.*EmWeb", banner:banner );
set_mandatory_key( key:"expressjs", regex:"X-Powered-By\s*:\s*Express", banner:banner );
set_mandatory_key( key:"fexsrv", regex:"^Server\s*:\s*fexsrv", banner:banner );
set_mandatory_key( key:"filemaker", regex:"^Server\s*:\s*FileMaker", banner:banner );
set_mandatory_key( key:"firstclass", regex:"^Server\s*:.*FirstClass.*", banner:banner );
set_mandatory_key( key:"gunicorn", regex:"^Server\s*:\s*gunicorn", banner:banner );
set_mandatory_key( key:"h2o", regex:"^Server\s*:\s*h2o", banner:banner );
set_mandatory_key( key:"http_server", regex:"^Server\s*:\s*http server", banner:banner );
set_mandatory_key( key:"httpd", regex:"^Server\s*:\s*httpd", banner:banner );
set_mandatory_key( key:"httpdx", regex:"httpdx", banner:banner, extra_key:"www_or_ftp/httpdx/detected" );
set_mandatory_key( key:"iSpy", regex:"^Server\s*:\s*iSpy", banner:banner );
set_mandatory_key( key:"iTunes", regex:"^DAAP-Server\s*:\s*iTunes", banner:banner );
set_mandatory_key( key:"iWeb", regex:"^Server\s*:\s*iWeb", banner:banner );
set_mandatory_key( key:"icecast", regex:"icecast", banner:banner );
set_mandatory_key( key:"idea_webserver", regex:"^Server\s*:\s*IdeaWebServer", banner:banner );
set_mandatory_key( key:"intrasrv", regex:"^Server\s*:\s*intrasrv", banner:banner );
set_mandatory_key( key:"jHTTPd", regex:"^Server\s*:\s*jHTTPd", banner:banner );
set_mandatory_key( key:"jigsaw", regex:"^Server\s*:\s*Jigsaw", banner:banner );
set_mandatory_key( key:"kfweb", regex:"^Server\s*:.*KeyFocus Web Server.*", banner:banner );
set_mandatory_key( key:"kibana", regex:"kbn-name\s*:\s*kibana", banner:banner );
set_mandatory_key( key:"kolibri", regex:"^Server\s*:\s*kolibri", banner:banner );
set_mandatory_key( key:"libsoup", regex:"^Server\s*:\s*(soup-transcode-proxy )?libsoup", banner:banner );
set_mandatory_key( key:"lighttpd", regex:"^(Server\s*:\s*lighttpd|\s*If you find a bug in this Lighttpd package, or in Lighttpd itself, please file a bug report on it\.)", banner:banner, main_page_res:main_page_res );
set_mandatory_key( key:"limewire", regex:"limewire", banner:banner );
set_mandatory_key( key:"linksys", regex:"linksys", banner:banner );
set_mandatory_key( key:"linuxconf", regex:"^Server\s*:.*linuxconf.*", banner:banner );
set_mandatory_key( key:"lwIP", regex:"^Server\s*:\s*lwIP", banner:banner );
# nb: Keep in sync with the pattern in gsf/gb_meinberg_lantime_http_detect.nasl
set_mandatory_key( key:"meinberg_lantime", regex:'^\\s*([Ss]erver\\s*:\\s*LANTIME|<TITLE>Welcome to LANTIME[^<]*</TITLE>|[Ww]{3}-[Aa]uthenticate\\s*:\\s*Basic realm="LANTIME Web Interface")', banner:banner, main_page_res:main_page_res );
set_mandatory_key( key:"micro_httpd", regex:"^Server\s*:\s*micro_httpd", banner:banner );
set_mandatory_key( key:"minaliC", regex:"^Server\s*:\s*minaliC", banner:banner );
set_mandatory_key( key:"mini_httpd", regex:"^Server\s*:\s*mini_httpd", banner:banner );
set_mandatory_key( key:"mini_httpd_or_thttpd", regex:"^Server\s*:\s*(mini_|t)httpd", banner:banner );
set_mandatory_key( key:"miniupnp", regex:"miniupnp", banner:banner );
set_mandatory_key( key:"mod_jk", regex:"^Server\s*:.*mod_jk", banner:banner, extra_key:"mod_jk_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"mod_perl", regex:"^Server\s*:.*mod_perl", banner:banner, extra_key:"mod_perl_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"mod_python", regex:"^Server\s*:.*mod_python", banner:banner, extra_key:"mod_python_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"mod_ssl", regex:"^Server\s*:.*mod_ssl", banner:banner, extra_key:"mod_ssl_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"monit", regex:'(^Server\\s*:\\s*monit|WWW-Authenticate\\s*:\\s*Basic\\s+realm="monit")', banner:banner );
set_mandatory_key( key:"mt-daapd", regex:"^Server\s*:\s*mt-daapd", banner:banner );
set_mandatory_key( key:"myCIO", regex:"myCIO", banner:banner );
set_mandatory_key( key:"ncsa", regex:"^Server\s*:\s*NCSA", banner:banner );
set_mandatory_key( key:"netcache", regex:"^Server\s*:\s*NetCache", banner:banner );
set_mandatory_key( key:"netcam", regex:'Basic realm="netcam"', banner:banner );
set_mandatory_key( key:"netgear/device", regex:"NETGEAR", banner:banner );
set_mandatory_key( key:"netware", regex:"^Server\s*:\s*NetWare", banner:banner );
set_mandatory_key( key:"nghttpx", regex:"^Server\s*:\s*nghttpx", banner:banner );
set_mandatory_key( key:"nginx", regex:"^Server\s*:\s*nginx", banner:banner );
set_mandatory_key( key:"nostromo", regex:"^Server\s*:\s*nostromo", banner:banner );
set_mandatory_key( key:"ntop", regex:"^Server\s*:\s*ntop", banner:banner );
set_mandatory_key( key:"oaohi", regex:"Oracle Applications One-Hour Install", banner:banner );
set_mandatory_key( key:"onehttpd", regex:"^Server\s*:\s*onehttpd", banner:banner );
set_mandatory_key( key:"oracle/iplanet_web_proxy_server", regex:"^Server\s*:\s*Oracle-iPlanet-Web-Proxy-Server", banner:banner );
set_mandatory_key( key:"payara_server", regex:"^(Server\s*:\s*Payara\s*Server|X-Powered-By\s*:\s*Servlet\/([0-9.]+)\s*JSP\/([0-9.]+)\s*\(Payara\s*Server)", banner:banner );
set_mandatory_key( key:"payara_micro", regex:"^Server\s*:\s*Payara\s*Micro", banner:banner );
set_mandatory_key( key:"powerfolder", regex:"powerfolder", banner:banner );
set_mandatory_key( key:"puppet", regex:"X-Puppet-Version\s*:", banner:banner );
set_mandatory_key( key:"python", regex:"^Server\s*:.*Python", banner:banner, extra_key:"python_or_apache_status_info_error_pages/banner" );
set_mandatory_key( key:"rXpress", regex:"^Server\s*:\s*rXpress", banner:banner );
set_mandatory_key( key:"sambar", regex:"^Server\s*:\s*SAMBAR", banner:banner );
set_mandatory_key( key:"sap", regex:"^Server\s*:\s*SAP ", banner:banner, extra_key:"sap/products/http/detected" );
set_mandatory_key( key:"sap/netweaver/as", regex:"^Server\s*:\s*SAP NetWeaver Application Server", banner:banner, extra_keys:make_list( "sap/netweaver/as/http/detected", "sap/products/http/detected" ) );
set_mandatory_key( key:"sap/netweaver/as_abap", regex:"^server\s*:\s*SAP NetWeaver Application Server [^/]*/ ABAP", banner:banner, extra_keys:make_list( "sap/netweaver/as/http/detected", "sap/products/http/detected" ) );
set_mandatory_key( key:"sap/netweaver/as_icm", regex:"^server\s*:\s*SAP NetWeaver Application Server [^/]*/ ICM", banner:banner, extra_keys:make_list( "sap/netweaver/as/http/detected", "sap/products/http/detected" ) );
set_mandatory_key( key:"sap/netweaver/as_java", regex:"^server\s*:\s*SAP NetWeaver Application Server [^/]*/ AS Java", banner:banner, extra_keys:make_list( "sap/netweaver/as/http/detected", "sap/products/http/detected" ) );
set_mandatory_key( key:"sdk_for_upnp", regex:"sdk for upnp", banner:banner );
set_mandatory_key( key:"shoutcast", regex:"shoutcast", banner:banner );
set_mandatory_key( key:"spidercontrol-scada", regex:"^Server\s*:\s*SCADA.*\(powered by SpiderControl TM\)", banner:banner );
set_mandatory_key( key:"squid", regex:"^Server\s*:.*Squid.*", banner:banner );
# e.g. Set-Cookie: SoftPLC= for Tecomat Foxtrot
set_mandatory_key( key:"softplc", regex:"SoftPLC", banner:banner );
set_mandatory_key( key:"stronghold", regex:"^Server\s*:\s*Stronghold", banner:banner );
set_mandatory_key( key:"stweb", regex:"^Server\s*:.*StWeb-MySql", banner:banner );
set_mandatory_key( key:"sun_oracle/web_servers", regex:'^((Server|Proxy-agent)\\s*:\\s*(Oracle-iPlanet-Web-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server)|Www-authenticate\\s*:\\s*Basic realm="Oracle iPlanet Web Server")', banner:banner );
set_mandatory_key( key:"surgeftp", regex:'Basic realm="surgeftp', banner:banner );
set_mandatory_key( key:"surgemail", regex:"surgemail", banner:banner );
set_mandatory_key( key:"swebs", regex:"^Server\s*:\s*swebs", banner:banner );
set_mandatory_key( key:"theserver", regex:"^Server\s*:\s*TheServer", banner:banner );
set_mandatory_key( key:"thin", regex:"^Server\s*:\s*thin", banner:banner );
set_mandatory_key( key:"thttpd", regex:"^Server\s*:\s*thttpd", banner:banner );
set_mandatory_key( key:"thttpd-alphanetworks", regex:"thttpd-alphanetworks", banner:banner );
set_mandatory_key( key:"tigershark", regex:"^Server\s*:.*tigershark", banner:banner );
set_mandatory_key( key:"titanftp", regex:"^Server\s*:.*Titan FTP Server", banner:banner );
set_mandatory_key( key:"tplink_httpd", regex:"^Server\s*:\s*TP-LINK HTTPD", banner:banner );
set_mandatory_key( key:"tracd", regex:"^Server\s*:\s*tracd", banner:banner );
set_mandatory_key( key:"tripwire", regex:"^Server\s*:\s*Apache.* Intrusion", banner:banner );
set_mandatory_key( key:"tux", regex:"^Server\s*:.*TUX", banner:banner );
set_mandatory_key( key:"twistedweb", regex:"^Server\s*:.*TwistedWeb/", banner:banner );
set_mandatory_key( key:"uIP", regex:"^Server\s*:\s*uIP/", banner:banner );
set_mandatory_key( key:"uc_httpd", regex:"^Server\s*:\s*uc-httpd", banner:banner );
set_mandatory_key( key:"uhttps", regex:"^Server\s*:\s*uhttps", banner:banner );
set_mandatory_key( key:"vncviewer_jc", regex:"vncviewer\.(jar|class)", banner:banner );
set_mandatory_key( key:"voipnow", regex:"^Server\s*:\s*voipnow", banner:banner );
set_mandatory_key( key:"vqServer", regex:"^Server\s*:\s*vqServer", banner:banner );
set_mandatory_key( key:"webcam_7_xp", regex:"^Server\s*:\s*(webcam 7|webcamXP)", banner:banner );
set_mandatory_key( key:"webmin_usermin", regex:"^Server\s*:.*MiniServ.*", banner:banner );
set_mandatory_key( key:"websitepro", regex:"^Server\s*:\s*WebSitePro", banner:banner );
set_mandatory_key( key:"webshield_appliance", regex:"^Server\s*:\s*WebShield Appliance", banner:banner );
set_mandatory_key( key:"webstar", regex:"^Server\s*:\s*WebSTAR", banner:banner );
set_mandatory_key( key:"wise", regex:"^Server\s*:\s*WISE-4000", banner:banner );
set_mandatory_key( key:"wnr2000", regex:'Basic realm="NETGEAR wnr2000', banner:banner );
set_mandatory_key( key:"wodWebServer", regex:"wodWebServer", banner:banner );
set_mandatory_key( key:"wowza_streaming_engine", regex:"^Server\s*:\s*WowzaStreamingEngine", banner:banner );
set_mandatory_key( key:"www_fileshare_pro", regex:"^Server\s*:\s*WWW File Share Pro", banner:banner );
set_mandatory_key( key:"yawcam", regex:"^Server\s*:\s*yawcam", banner:banner );
set_mandatory_key( key:"zope", regex:"Zope", banner:banner );
set_mandatory_key( key:"polycom_telephone", regex:"^Server\s*:\s*Poly(com)? .*Telephone HTTPd", banner:banner );

exit( 0 );
