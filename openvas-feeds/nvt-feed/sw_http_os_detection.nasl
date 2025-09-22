# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Reworked, improved and extended detection code and pattern since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111067");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-12-10 16:00:00 +0100 (Thu, 10 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "sw_apcu_info.nasl", "gb_phpinfo_output_detect.nasl"); # nb: Both are setting a possible existing banner used by check_php_banner()
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based OS detection from the HTTP/PHP banner or default test
  pages.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (HTTP)";

function check_http_banner( port, banner ) {

  local_var port, banner, banner_type, version;

  banner = chomp( banner );
  if( ! banner )
    return;

  # nb:
  # - More detailed OS detection in gsf/gb_spinetix_player_http_detect.nasl
  # - This needs to be before the Server checks below because these devices are also exposing a
  #   banner like e.g. Server: Apache/2.2.31 (Unix)
  if( _banner = egrep( string:banner, pattern:"^X-spinetix-(firmware|serial|hw)\s*:", icase:TRUE ) ) {
    os_register_and_report( os:"SpinetiX Digital Signage Unknown Model Player Firmware", cpe:"cpe:/o:spinetix:unknown_model_firmware", banner_type:"SpinetiX Digital Signage HTTP banner", port:port, banner:chomp( _banner ), desc:SCRIPT_DESC, runs_key:"unixoide" );
    return;
  }

  if( banner = egrep( pattern:"^Server\s*:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    # Server: Oracle-iPlanet-Web-Server/7.0
    # Server: Sun-Java-System-Web-Server/7.0
    # Server: Sun-ONE-Web-Server/6.1
    # Server: Oracle-iPlanet-Web-Proxy-Server/4.0
    # These are cross-platform
    if( banner =~ "^Server\s*:\s*(Oracle-iPlanet-Web(-Proxy)?-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server)(/[0-9.]+)?$" )
      return;

    # Server: Apereo CAS
    # Java and cross-platform
    if( banner =~ "^Server\s*:\s*Apereo CAS" )
      return;

    if( banner =~ "^Server\s*:\s*AirTunes(/[0-9.]+)?$" )
      return;

    # uIP (micro IP) TCP/IP network ip stack. Running on embedded systems
    # not tied to a specific OS.
    if( "Server: uIP/" >< banner )
      return;

    # FNET TCP/IP network ip stack. Running on embedded systems
    # not tied to a specific OS.
    if( "Server: FNET HTTP" >< banner )
      return;

    # Running on CODESYS runtime which is cross-platform
    # nb: Missing space after ":" is expected.
    if( "Server:ENIServer" >< banner )
      return;

    # Bea/Oracle WebLogic is cross-platform
    if( "Server: WebLogic" >< banner )
      return;

    # WIBU Systems CodeMeter Web Admin is cross-platform
    if( "WIBU-SYSTEMS HTTP Server" >< banner )
      return;

    # Apache Spark is cross-platform
    if( banner == "Server: Spark" )
      return;

    # Lotus Domino is cross-platform
    if( banner == "Server: Lotus-Domino" ||
        banner == "Server: Lotus Domino" ) return;

    # BigIP Load Balancer on the frontend, registering this could report/use a wrong OS for the backend server
    if( banner == "Server: BigIP" ) return;

    # aMule Server is cross-patform
    if( banner == "Server: aMule" ) return;

    # Transmission Server is cross-platform
    if( banner == "Server: Transmission" ) return;

    # Logitech Media Server is cross-platform
    if( banner == "Server: Logitech Media Server" ||
        egrep( pattern:"^[Ss]erver\s*:\s*Logitech Media Server \([0-9.]+\)$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*Logitech Media Server \([0-9.]+ - [0-9.]+)$", string:banner ) )
      return;

    # NZBGet is cross-platform
    if( "Server: nzbget" >< banner ) return;

    # API TCP listener is cross-platform
    if( "Server: Icinga" >< banner ) return;

    # Runs on Windows, Linux and Mac OS X
    if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner ) return;

    # Server: SentinelProtectionServer/7.3
    # Server: SentinelKeysServer/1.3.2
    # Seems to be running on Windows and NetWare systems.
    if( "SentinelProtectionServer" >< banner || "SentinelKeysServer" >< banner ) return;

    # Server: EWS-NIC5/15.18
    # Server: EWS-NIC5/96.55
    # Running on different printers from e.g. Xerox, Dell or Epson. The OS is undefined so just return...
    if( egrep( pattern:"^[Ss]erver\s*:\s*EWS-NIC5/[0-9.]+$", string:banner ) ) return;

    # Server: CTCFC/1.0
    # Commtouch Anti-Spam Daemon (ctasd.bin) running on Windows and Linux (e.g. IceWarp Suite)
    if( egrep( pattern:"^[Ss]erver\s*:\s*CTCFC/[0-9.]+$", string:banner ) ) return;

    # e.g. Server: SimpleHTTP/0.6 Python/2.7.5 -> Python is cross-platform
    if( egrep( pattern:"^[Ss]erver\s*:\s*SimpleHTTP/[0-9.]+ Python/[0-9.]+$", string:banner ) ) return;

    # e.g.:
    # Server: Python/3.8 aiohttp/3.6.2
    # Server: aiohttp/3.6.2
    # -> Python is cross-platform
    if( egrep( pattern:"^[Ss]erver\s*:\s*(Python/[0-9.]+ )?aiohttp/[0-9.]+$", string:banner, icase:FALSE ) ) return;

    # e.g.
    # Server: BaseHTTP/0.6 Python/3.7.3
    # Server: BaseHTTP/0.3 Python/2.7.15rc1
    # Server: BaseHTTP/0.3 Python/2.7.12+
    # -> Python is cross-platform
    if( egrep( pattern:"^[Ss]erver\s*:\s*BaseHTTP/[0-9.]+ Python/[0-9.]+(rc[0-9]+|\+)?$", string:banner ) ) return;

    # e.g. Server: MX4J-HTTPD/1.0 -> Java implementation, cross-patform
    if( egrep( pattern:"^[Ss]erver\s*:\s*MX4J-HTTPD/[0-9.]+$", string:banner ) ) return;

    # e.g. Server: libwebsockets or server: libwebsockets
    if( egrep( pattern:"^Server\s*:\s*libwebsockets$", string:banner, icase:TRUE ) ) return;

    # e.g. Server: mt-daapd/svn-1696 or Server: mt-daapd/0.2.4.1
    # Cross-platform
    if( egrep( pattern:"^Server\s*:\s*mt-daapd/?([0-9.]+|svn-[0-9]+)?$", string:banner, icase:TRUE ) ) return;

    # e.g. Server: Mongoose/6.3 or Server: Mongoose
    # Cross-platform
    if( egrep( pattern:"^Server\s*:\s*Mongoose/?[0-9.]*$", string:banner, icase:TRUE ) ) return;

    # e.g.:
    # Server: WSO2 Carbon Server
    # server: WSO2 Carbon Server
    # Cross-platform (Java)
    if( egrep( pattern:"^[Ss]erver\s*:\s*WSO2 Carbon Server", string:banner ) ) return;

    # e.g. Server: ELOG HTTP 2.9.0-2396
    # Runs on Linux/Unixoide and Windows
    if( egrep( pattern:"^[Ss]erver\s*:\s*ELOG HTTP", string:banner ) ) return;

    # e.g.
    # Server: openresty
    # Server: openresty/1.11.2.5
    # Cross-platform
    if( egrep( pattern:"^Server\s*:\s*openresty/?[0-9.]*$", string:banner, icase:TRUE ) ) return;

    # Runs on Windows, Linux, Unix according to https://download.manageengine.com/products/applications_manager/meam_fact_sheet.pdf
    if( egrep( pattern:"^Server\s*:\s*AppManager", string:banner, icase:TRUE ) ) return;

    # e.g.
    # server: SAP NetWeaver Application Server 7.49 / AS Java 7.50
    # server: SAP NetWeaver Application Server / ABAP 731
    # server: SAP NetWeaver Application Server 7.11 / ICM 7.11
    # server: SAP NetWeaver Application Server
    # Cross-platform
    if( egrep( pattern:"^server\s*:\s*SAP NetWeaver Application Server", string:banner, icase:TRUE ) ) return;

    # e.g.
    # server: SAP J2EE Engine/7.00
    # Cross-platform (Java)
    if( egrep( pattern:"^server\s*:\s*SAP J2EE Engine", string:banner, icase:TRUE ) ) return;

    # e.g.:
    # Server: WEBrick/1.3.1
    # Server: WEBrick/1.3.1 (Ruby/1.8.7/2013-06-27) OpenSSL/1.0.1e
    # Server: WEBrick/1.3.1 (Ruby/2.0.0/2014-05-08)
    # Cross-platform and no OS info included.
    if( egrep( pattern:"^Server\s*:\s*WEBrick/([0-9.]+)(\s*\(Ruby/([0-9.]+)[^\)]+\))?(\s*OpenSSL/([0-9a-z.]+))?$", string:banner, icase:TRUE ) ) return;

    # No OS info included, e.g.:
    # Server: Cherokee/0.2.7
    # Server: Cherokee
    #
    # There are a few like the following including the OS info which are evaluated later:
    # Server: Cherokee/1.2.101 (Ubuntu)
    # Server: Cherokee/1.2.103 (Arch Linux)
    # Server: Cherokee/1.2.101 (Debian GNU/Linux)
    # Server: Cherokee/1.2.104 (Debian)
    # Server: Cherokee/1.2.101 (UNIX)
    # Server: Cherokee/0.99.39 (Gentoo Linux)
    if( egrep( pattern:"^Server\s*:\s*Cherokee(/[0-9.]+)?$", string:banner, icase:TRUE ) ) return;

    # Runs on various OS (Linux/Unix), a Windows Port exists and the product might be even run without a OS (according to the vendor). e.g.:
    # Server: lwIP/1.4.0 (http://savannah.nongnu.org/projects/lwip)
    if( egrep( pattern:"^Server\s*:\s*lwIP", string:banner, icase:TRUE ) ) return;

    # Runs on Windows, Linux, Unix according to the following text in its documentation:
    # "The architecture has been designed so that it can be ported to various operating system platforms. Currently Windows and those Unix platforms on which the Web Application Server runs are currently supported."
    if( egrep( pattern:"^Server\s*:\s*SAP Internet Graphics Server", string:banner, icase:TRUE ) ) return;

    # Seen on D-Link DSR- devices, unclear if other products are running these as well so exclude them for now
    if( egrep( pattern:"^Server\s*:\s*(Light Weight Web Server|Embedded HTTP Server\.)$", string:banner, icase:TRUE ) ) return;

    # Cross-platform (Java)
    if( egrep( pattern:"^Server\s*:\s*Apache TomEE", string:banner, icase:TRUE ) ) return;

    # Seen on Samsung WLAN AP devices but also on devices having "IP Dect -" in the page title.
    # Currently unknown if this is Linux only so excluding them for now. e.g.:
    # Server: Chunjs/Server
    if( egrep( pattern:"^Server\s*:\s*Chunjs/Server", string:banner, icase:TRUE ) ) return;

    # Seen on Schneider PowerLogic but that software might run on various different devices. e.g.:
    # Server: HyperX/1.0 (ThreadX)
    # Server: HyperX/1.0 ( ThreadX )
    if( egrep( pattern:"^Server\s*:\s*HyperX/[0-9.]+ \(\s*ThreadX\s*\)$", string:banner, icase:TRUE ) ) return;

    # Seen on Aruba / HP / HPE / ProCurve Switch devices and Aruba Instant but that web server might
    # run on different devices so exclude it for now. e.g.:
    # Server: eHTTP v2.0
    if( egrep( pattern:"^Server\s*:\s*eHTTP\s*v2\.0$", string:banner, icase:TRUE ) ) return;

    # Cross-platform (kweb seems to be a component of Kopano)
    if( egrep( pattern:"^Server\s*:\s*(Kopano|Caddy|kweb)$", string:banner, icase:TRUE ) ) return;

    # Cross-platform (Runs on Windows, Linux/Unix and macOS), e.g.:
    # Server: TwistedWeb/20.3.0dev0
    # Server: Twisted/13.0.0 TwistedWeb/9.0.0
    # Server: TwistedWeb/16.4.0
    # Server: Twisted/13.2.0 TwistedWeb/[twisted.web2, version 8.1.0]
    if( egrep( pattern:"^Server\s*:.*TwistedWeb/", string:banner, icase:TRUE ) ) return;

    # Cross-platform (Java), e.g.:
    # Server: JBoss-EAP/7
    if( egrep( pattern:"^Server\s*:\s*JBoss-EAP(/[0-9.]+)?$", string:banner, icase:TRUE ) ) return;

    # Cross-platform (Java) similar to the above, e.g.:
    # Server: WildFly/8
    if( egrep( pattern:"^Server\s*:\s*WildFly(/[0-9.]+)?$", string:banner, icase:TRUE ) ) return;

    # Running on Windows, Linux and macOS according to https://docs.couchbase.com/server/current/install/install-platforms.html
    if( egrep( pattern:"^[Ss]erver\s*:\s*Couchbase Server$", string:banner, icase:FALSE ) ) return;

    # Cross-platform (JSP engine), e.g.:
    # Server: Resin/4.0.58
    if( banner =~ "^Server\s*:\s*Resin(/[0-9.]+)?$" )
      return;

    # Cross-platform (Java), e.g.:
    # Server: JRun Web Server
    # Server: JRun Web Server/3.0
    if( banner =~ "^Server\s*:\s*JRun Web Server" )
      return;

    # Cross-platform, e.g.:
    # Server: ATS
    # Server: ATS/9.1.10.57
    if( egrep( pattern:"^[Ss]erver\s*:\s*ATS(/[0-9.]+)?$", string:banner, icase:FALSE ) )
      return;

    # Cross-platform, usually just:
    # Server: CrushFTP HTTP Server
    if( egrep( pattern:"^[Ss]erver\s*:\s*CrushFTP HTTP Server$", string:banner, icase:FALSE ) )
      return;

    # Cross-platform, e.g.:
    # Server: Wing FTP Server
    # Server: Wing FTP Server(Free Edition)
    # Server: Wing FTP Server(<companyname_the_product_is_using>)
    if( egrep( pattern:"^[Ss]erver\s*:\s*Wing FTP Server", string:banner, icase:FALSE ) )
      return;

    # Running on at least Windows and macOS, e.g.:
    # Server: FileMakerPro/4.0
    # Server: FileMakerPro/6.0Jv3 WebCompanion/6.0Jv1
    if( egrep( pattern:"^[Ss]erver\s*:\s*FileMakerPro", string:banner, icase:FALSE ) )
      return;

    # Seems to run on Windows, Linux and macOS according to:
    # https://simple-help.com/server-requirements
    #
    # e.g.:
    # Server: SimpleHelp/SSuite-5-5-20240916-151140
    # Server: SimpleHelp/SSuite-4-4-20170213-185308
    if( egrep( pattern:"^[Ss]erver\s*:\s*SimpleHelp/SSuite", string:banner, icase:FALSE ) )
      return;

    # Both running on Java and thus cross-platform
    #
    # e.g.:
    #
    # Server: Payara Server 6.2025.1 #badassfish
    # Server: Payara Server Enterprise 5.73.0 <redacted>
    # Server: Payara Server  4.1.2.172 #badassfish
    # Server: Payara Micro #badassfish
    if( egrep( pattern:"^[Ss]erver\s*:\s*Payara (Server|Micro)", string:banner, icase:FALSE ) )
      return;

    if( banner == "Server:" ||
        banner == "Server: " ||
        banner == "Server: none" || # Seen on WatchGuard devices but is too generic
        banner == "Server: /" || # Seen on Maipu Network devices
        banner == "Server: server" || # Unknown
        banner == "Server: Server" || # Unknown, seen on 80/tcp
        banner == "Server: SERVER" || # Seen on Meinberg LANTIME devices but there might be more/different ones...
        banner == "server: uvicorn" || # Python -> cross-platform
        banner == "Server: Undefined" || # Unknown
        banner == "Server: WebServer" || # e.g. D-Link DIR- devices
        banner == "Server: squid" ||
        banner == "Server: nginx" ||
        banner == "Server: Apache" ||
        banner == "Server: lighttpd" ||
        banner == "Server: sfcHttpd" ||
        banner == "Server: Web" || # Seen on Trend Micro TippingPoint Security Management System (SMS) but might exist on other products as well...
        banner == "Server: Allegro-Software-RomPager" || # Vendor: "Works with any OS vendor and will function without an OS if needed"
        banner == "Server: Apache-Coyote/1.0" ||
        banner == "Server: Apache-Coyote/1.1" ||
        banner == "Server: HASP LM" || # Is running under windows and linux
        banner == "Server: Mbedthis-Appweb" || # Is running under various OS variants
        banner == "Server: Embedthis-Appweb" || # Is running under various OS variants
        banner == "Server: Embedthis-http" || # Is running under various OS variants
        banner == "Server: GoAhead-Webs" || # Is running under various OS variants
        banner == "Server: Mojolicious (Perl)" || # Cross-platform
        banner == "Server: Java/0.0" || # Cross-platform, running on e.g. VIBNODE devices
        banner == "Server: NessusWWW" || # Nessus could be running on Windows, Linux/Unix or Mac OS X
        banner == "Server: Embedded Web Server" ||
        banner == "Server: EZproxy" || # runs on Linux or Windows
        banner == "Server: com.novell.zenworks.httpserver" || # Cross-platform
        banner == "Server: Tableau" || # Runs at least on Linux and Windows
        banner == "Server: PAM360" || # ManageEngine PAM360. Runs at least on Linux and Windows
        banner == "Server: Security Console" || # Rapid7 InsightVM or Nexpose can run on Linux and Windows
        "erver: BBC " >< banner || # OV Communication Broker runs on various different OS variants
        "Server: PanWeb Server/" >< banner || # Already covered by gb_paloalto_panos_http_detect.nasl
        egrep( pattern:"^[Ss]erver\s*:\s*com\.novell\.zenworks\.httpserver/[0-9.]+$", string:banner ) || # Cross-platform, e.g. Server: com.novell.zenworks.httpserver/1.0
        egrep( pattern:"^[Ss]erver\s*:\s*DHost/[0-9.]+ HttpStk/[0-9.]+$", string:banner ) || # DHost/9.0 HttpStk/1.0 from Novell / NetIQ eDirectory, runs on various OS variants
        egrep( pattern:"^[Ss]erver\s*:\s*Tomcat/[0-9.]+$", string:banner ) || # Quite outdated Tomcat, e.g. Server: Tomcat/2.1
        egrep( pattern:"^[Ss]erver\s*:\s*Themis [0-9.]+$", string:banner ) || # Currently unknown
        egrep( pattern:"^[Ss]erver\s*:\s*Mordac/[0-9.]+$", string:banner ) || # Currently unknown
        egrep( pattern:"^[Ss]erver\s*:\s*eHTTP v[0-9.]+$", string:banner ) || # Currently unknown, have seen this on HP ProCurves but also on some login pages without any info
        egrep( pattern:"^[Ss]erver\s*:\s*Agranat-EmWeb/[0-9_R]+$", string:banner ) || # Currently unknown, might be an Alcatel device...
        egrep( pattern:"^[Ss]erver\s*:\s*gSOAP/[0-9.]+$", string:banner ) || # Cross-platform
        egrep( pattern:"^[Ss]erver\s*:\s*squid/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*squid/[0-9.]+\.STABLE[0-9.]+$", string:banner ) || # e.g. Server: squid/2.7.STABLE5
        egrep( pattern:"^[Ss]erver\s*:\s*Jetty\([0-9.v]+\)$", string:banner ) || # e.g. Server: Jetty(7.3.1.v20110307)
        egrep( pattern:"^[Ss]erver\s*:\s*Jetty\([0-9.]+z-SNAPSHOT\)$", string:banner ) || # e.g. Server: Jetty(9.2.z-SNAPSHOT) or Server: Jetty(9.3.z-SNAPSHOT)
        egrep( pattern:"^[Ss]erver\s*:\s*Jetty\(winstone-[0-9.]+\)$", string:banner ) || # e.g. Server: Jetty(winstone-2.8)
        egrep( pattern:"^[Ss]erver\s*:\s*nginx/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*Apache/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*lighttpd/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*CompaqHTTPServer/[0-9.]+$", string:banner ) || # HP SMH, cross-platform, e.g. Server: CompaqHTTPServer/2.1
        egrep( pattern:"^[Ss]erver\s*:\s*http server [0-9.]+$", string:banner ) || # e.g. Server: http server 1.0
        egrep( pattern:"^[Ss]erver\s*:\s*Web Server [0-9.]+$", string:banner ) || # e.g. Server: Web Server 1.1
        egrep( pattern:"^[Ss]erver\s*:\s*Web Server$", string:banner ) || # e.g. Server: Web Server
        egrep( pattern:"^[Ss]erver\s*:\s*MiniServ/[0-9.]+$", string:banner ) || # From Webmin/Usermin, cross-platform,  e.g. Server: MiniServ/1.550
        egrep( pattern:"^[Ss]erver\s*:\s*RealVNC/[0-9.]+$", string:banner ) || # Cross-platform, e.g. Server: RealVNC/4.0
        egrep( pattern:"^[Ss]erver\s*:\s*HASP LM/[0-9.]+$", string:banner ) || # Is running under windows and linux
        egrep( pattern:"^[Ss]erver\s*:\s*Mbedthis-Appweb/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^[Ss]erver\s*:\s*Embedthis-http/[0-9.]+$", string:banner ) || # Is running under various OS variants, banner e.g. Server: Embedthis-http/4.0.0
        egrep( pattern:"^[Ss]erver\s*:\s*Embedthis-Appweb/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^[Ss]erver\s*:\s*GoAhead-Webs/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^[Ss]erver\s*:\s*Allegro-Software-RomPager/[0-9.]+$", string:banner ) || # Vendor: "Works with any OS vendor and will function without an OS if needed"
        egrep( pattern:"^[Ss]erver\s*:\s*CompaqHTTPServer/[0-9.]+ HPE? System Management Homepage$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^[Ss]erver\s*:\s*CompaqHTTPServer/[0-9.]+ HPE? System Management Homepage/[0-9.]+$", string:banner ) || # e.g. Server: CompaqHTTPServer/9.9 HP System Management Homepage/2.1.2.127, is running under various OS variants
        # Runs on Linux/Unix but could be also installed on Docker on Windows WSL. e.g.:
        # Server: APISIX
        # Server: APISIX/2.12.1
        egrep( pattern:"^[Ss]erver\s*:\s*APISIX(/[0-9.])?$", string:banner ) ||
        egrep( pattern:"^[Ss]erver\s*:\s*Payara Server +[0-9.]+ #badassfish$", string:banner ) ) { # Cross-platform, e.g. Server: Payara Server  4.1.2.172 #badassfish
      return;
    }

    # Seen on e.g. EulerOS. There might be others Distros using the same so we're ignoring this for now...
    # Server: Apache/2.4.6 () mod_auth_gssapi/1.3.1 mod_nss/1.0.14 NSS/3.28.4 mod_wsgi/3.4 Python/2.7.5
    if( egrep( pattern:"^Server\s*:\s*Apache/[0-9.]+ \(\)(( (mod_auth_gssapi|mod_nss|NSS|mod_wsgi|Python)/[0-9.]+)*)?$", string:banner, icase:TRUE ) )
      return;

    banner_type = "HTTP Server banner";

    # nb: Keep the UPnP pattern in sync with gb_upnp_os_detection.nasl for the UDP counterpart...

    # SERVER: Ubuntu/7.10 UPnP/1.0 miniupnpd/1.0
    # Server: Ubuntu/10.10 UPnP/1.0 miniupnpd/1.0
    # SERVER: Ubuntu/hardy UPnP/1.0 MiniUPnPd/1.2
    # SERVER: Ubuntu/lucid UPnP/1.0 MiniUPnPd/1.4
    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Ubuntu versions. Still keep them in here as we can't know...
    if( egrep( pattern:"^SERVER\s*:\s*Ubuntu", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"SERVER\s*:\s*Ubuntu/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/warty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/hoary" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/breezy" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/dapper" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/edgy" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/feisty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/gutsy" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/hardy" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/intrepid" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/jaunty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/karmic" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/lucid" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/maverick" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/natty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/oneiric" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/precise" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/quantal" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/raring" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/saucy" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/trusty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/utopic" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/vivid" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/wily" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/xenial" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/yakkety" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/zesty" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/artful" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/bionic" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/cosmic" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/disco" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/eoan" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/focal" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Server: Debian/5.0.10 UPnP/1.0 MiniUPnPd/1.6
    # Server: Debian/4.0 UPnP/1.0 miniupnpd/1.0
    # Server: Debian/squeeze/sid UPnP/1.0 miniupnpd/1.0
    # SERVER: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.2
    # Server: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.6
    # SERVER: Debian/lenny UPnP/1.0 MiniUPnPd/1.2
    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Debian versions. Still keep them in here as we can't know...
    if( egrep( pattern:"^Server\s*:\s*Debian", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server\s*:\s*Debian/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/bookworm" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/bullseye" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/buster" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/stretch" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/jessie" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/wheezy" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/squeeze" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/lenny" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/etch" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/sarge" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/woody" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/potato" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/slink" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/hamm" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/bo" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/rex" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/buzz" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Server: CentOS/5.6 UPnP/1.0 MiniUPnPd/1.6
    # Server: CentOS/6.2 UPnP/1.0 miniupnpd/1.0
    # Server: CentOS/5.5 UPnP/1.0 MiniUPnPd/1.6
    if( egrep( pattern:"^Server\s*:\s*CentOS", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server\s*:\s*CentOS/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"CentOS", version:version[1], cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # TODO: There are more UPnP implementations reporting the OS:
    # SERVER: FreeBSD/8.1-PRERELEASE UPnP/1.0 MiniUPnPd/1.4
    # SERVER: FreeBSD/9 UPnP/1.0 MiniUPnPd/1.4
    # Server: FreeBSD/8.0-RC1 UPnP/1.0 MiniUPnPd/1.2
    # Server: SUSE LINUX/11.3 UPnP/1.0 miniupnpd/1.0
    # Server: Fedora/8 UPnP/1.0 miniupnpd/1.0
    # SERVER: Fedora/10 UPnP/1.0 MiniUPnPd/1.4

    # Server: MS .NET Remoting, MS .NET CLR 4.0.30319.42000
    if( "MS .NET Remoting" >< banner || "MS .NET CLR" >< banner ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: cisco-IOS
    # Server: cisco-IOS/12.0 HTTP-server/1.0(1)
    if( egrep( pattern:"^[Ss]erver\s*:\s*cisco-IOS", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix/Linux/BSD
    # e.g. Server: GoTTY/0.0.12
    # Server: Boa/0.94.14rc21
    if( egrep( pattern:"^[Ss]erver\s*:\s*(GoTTY|Boa)", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # "Mathopd is a very small, yet very fast HTTP server for UN*X systems."
    # e.g. Server: Mathopd/1.5p6
    if( egrep( pattern:"^[Ss]erver\s*:\s*Mathopd", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Microsoft-WinCE" >< banner ) {
      # e.g. Server: Microsoft-WinCE/5.0
      version = eregmatch( pattern:"Microsoft-WinCE/([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Microsoft Windows CE", version:version[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      } else {
        os_register_and_report( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      }
      return;
    }

    # Server: Jetty/4.2.x (VxWorks/WIND version 2.6 coldfire java/1.1-rr-std-b12)
    # Server: Apache/1.3.29 (VxWorks) mod_ssl/2.8.16 OpenSSL/0.9.7d
    # Server: M1 WebServer/2.0-VxWorks
    # Server: Jetty/5.1.x (VxWorks/VxWorks5.5.1 mips java/Java ME PBP 1.1
    if( "VxWorks" >< banner ) {
      os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # TrentMicro OfficeScan Client runs only on Windows
    if( egrep( pattern:"^[Ss]erver\s*:\s*OfficeScan Client", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Cassini runs only on Windows
    # e.g.
    # Server: Microsoft-Cassini/1.0.32007.0
    # Server: Cassini/4.0.1.6
    # Server: CassiniEx/4.4.1409.0
    if( banner =~ "Server\s*:\s*(Microsoft-)?Cassini" ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # UltiDev Cassini runs only on Windows
    # e.g.
    # Server: UltiDev Cassini/2.1.4.3
    if( egrep( string:banner, pattern:"^[Ss]erver\s*:\s*UltiDev Cassini", icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Samsung AllShare Server runs only on Windows
    # e.g.
    # SERVER: UPnP/1.1 Samsung AllShare Server/1.0
    # SERVER: Samsung AllShare Server/1.0
    if( banner =~ "SERVER\s*:\s*(UPnP/[0-9]\.[0-9]\s*)?Samsung AllShare Server" ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # ArgoSoft Mail Server runs only on Windows
    # e.g.
    # Server: ArGoSoft Mail Server Pro for WinNT/2000/XP
    if( banner =~ "Server\s*:\s*ArGoSoft Mail Server" ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    if( banner == "Server: CPWS" ) {
      os_register_and_report( os:"Check Point Gaia", cpe:"cpe:/o:checkpoint:gaia_os", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: MoxaHttp/2.3
    # Server: MoxaHttp/2.2
    # Server: MoxaHttp/1.0
    # nb: Embedded Linux
    if( "MoxaHttp" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "NetApp" >< banner ) {
      # Server: NetApp/7.3.7
      # Server: NetApp//8.2.3P3
      version = eregmatch( pattern:"NetApp//?([0-9a-zA-Z.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # UPS / USV on embedded OS
    if( "ManageUPSnet Web Server" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Examples:
    # Server: Jetty/5.1.10 (Windows Server 2008/6.1 amd64 java/1.6.0_07
    # Server: Jetty/3.1.8 (Windows 7 6.1 x86)
    # Server: Jetty/5.1.10 (Windows Server 2008 R2/6.1 amd64 java/1.6.0_31
    # Server: Jetty/5.1.15 (Linux/2.6.27.45-crl i386 java/1.5.0
    # Server: Jetty/null (Windows Server 2008 6.0 x86)
    # Server: Jetty/4.2.22 (Windows Server 2016/10.0 amd64 java/1.8.0_201)
    # Server: Jetty/5.1.4 (Windows Server 2012/6.2 x86 java/1.7.0_76
    # Server: Jetty/5.1.x (Windows Server 2008 R2/6.1 amd64 java/1.7.0_51
    # Server: Jetty/5.1.11RC0 (Windows 8/6.2 x86 java/1.7.0_45
    # Server: Jetty/4.2.12 (Windows XP/5.1 x86 java/1.4.1_02)
    # Server: Jetty/5.1.2 (SunOS/5.10 x86 java/1.6.0_39
    # Server: Jetty/4.2.23 (SunOS/5.9 sparc java/1.4.2_04)
    # Server: Jetty/4.0.1 (SunOS 5.8 sparc)
    #
    # Note that the missing ")" above are expected / was seen like this on live systems.
    #
    # Note that at least for Windows Vista the "real" version code 6.0 doesn't match the ones shown below.
    # The Vista/6.2 was also observed on a Windows Server 2012 R2 (version code 6.3).
    # Server: Jetty/4.2.9 (Windows Vista/6.1 x86 java/1.5.0_11)
    # Server: Jetty/4.2.9 (Windows Vista/6.2 x86 java/1.5.0_11)
    # Server: Jetty/5.1.x (Windows Vista/6.2 x86 java/1.6.0_03)
    #
    # Similar happen for Windows 2000:
    # Server: Jetty/4.2.14 (Windows 2000/5.2 x86 java/1.3.1_02)
    # This might be Windows XP 64bit or Windows Server 2003.

    if( "Jetty/" >< banner ) {
      if( "(Windows" >< banner ) {
        if( "(Windows Server 2016" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 10" >< banner ) {
          os_register_and_report( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2012 R2" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 8.1" >< banner ) {
          os_register_and_report( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2012" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 8" >< banner ) {
          os_register_and_report( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2008 R2" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 7" >< banner ) {
          os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2008" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        # nb: See note on the Jetty banners above.
        if( "(Windows Vista" >< banner && "Vista/6.1" >!< banner && "Vista/6.2" >!< banner ) {
          os_register_and_report( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2003" >< banner || "(Windows 2003" >< banner ) {
          os_register_and_report( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows XP" >< banner ) {
          os_register_and_report( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 2000" >< banner && "2000/5.2" >!< banner ) {
          os_register_and_report( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }

        # Currently unknown but definitely not Windows NT:
        # Server: Jetty/5.1.4 (Windows NT (unknown)/6.2 x86 java/1.5.0_22
        # Server: Jetty/5.1.x (Windows NT (unknown)/10.0 amd64 java/1.8.0_121

        # nb: We also want to report an unknown OS if none of the above patterns for Windows is matching. See note on the Jetty banners about Vista above.
        if( "Vista" >!< banner && "Windows 2000" >!< banner )
          os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
        else
          banner += '\nNote: 6.2 and 6.1 version codes in the Vista Banner are actually no Windows Vista. Same is valid for Windows 2000 banners having 5.2 as the version code';

        os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );

        return;
      }

      if( "(Linux" >< banner ) {
        version = eregmatch( pattern:"\(Linux/([0-9.]+)", string:banner );
        if( ! isnull( version[1] ) ) {
          os_register_and_report( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }

      if( "(SunOS" >< banner ) {
        version = eregmatch( pattern:"\(SunOS(/| )([0-9.]+)", string:banner );
        if( ! isnull( version[2] ) ) {
          os_register_and_report( os:"SunOS", version:version[2], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }
    }

    if( "HPE-iLO-Server" >< banner || "HP-iLO-Server" >< banner ) {
      os_register_and_report( os:"HP iLO", cpe:"cpe:/o:hp:integrated_lights-out", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Cisco Secure Access Control Server
    if( banner =~ "ACS [0-9.]+" ) {
      os_register_and_report( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Microsoft-HTTPAPI" >< banner || ( "Apache" >< banner && ( "(Win32)" >< banner || "(Win64)" >< banner ) ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # MS Lync
    if( egrep( pattern:"^[Ss]erver\s*:\s*RTC/[56]\.0", string:banner ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # nb: More detailed OS detection in gb_microsoft_iis_http_detect.nasl which is e.g. also
    # following redirects or using additional 404 page fingerprinting to detect the product in more
    # detail.
    if( "Microsoft-IIS" >< banner ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    if( "(SunOS," >< banner || "(SunOS)" >< banner ) {
      os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "/NetBSD" >< banner ) {
      os_register_and_report( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "(FreeBSD)" >< banner || "-freebsd-" >< banner ) {
      os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "OpenBSD" >< banner ) {
      os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # http://archive.debian.org/debian/pool/main/a/apache2/
    # http://archive.debian.org/debian/pool/main/a/apache/
    # http://ftp.debian.org/debian/pool/main/a/apache2/
    if( "Apache/" >< banner && "Debian" >< banner ) {
      if( "Apache/1.3.9 (Unix) Debian/GNU" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/1.3.26 (Unix) Debian GNU/Linux" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/1.3.33 (Debian GNU/Linux)" >< banner || "Apache/2.0.54 (Debian GNU/Linux)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # Server: Apache/1.3.34 Ben-SSL/1.55 (Debian) PHP/4.4.4-8+etch6 mod_jk/1.2.18
      if( "Apache/1.3.34 (Debian)" >< banner || "Apache/2.2.3 (Debian)" >< banner || ( "Apache/1.3.34 Ben-SSL" >< banner && "(Debian)" >< banner ) ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.9 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.16 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.22 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.10 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.25 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.38 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.52 (Debian)" >< banner || "Apache/2.4.54 (Debian)" >< banner || "Apache/2.4.56 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.57 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # nb: These have been used in Buster, Bullseye and Bookworm so we're registering all for now
      # with the newest (Bookworm) first
      if( "Apache/2.4.59 (Debian)" >< banner || "Apache/2.4.65 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # nb: Those have been used Bullseye and Bookworm so we're registering both for now with the
      # newest (Bookworm) first
      if( "Apache/2.4.61 (Debian)" >< banner || "Apache/2.4.62 (Debian)" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    # e.g.
    # ZNC 1.6.5+deb1 - http://znc.in
    # ZNC 1.6.5+deb1~bpo8 - http://znc.in
    # ZNC 1.6.5+deb1+deb9u1 - http://znc.in
    # ZNC 1.7.2+deb3 - http://znc.in -> This is on Debian 10
    # ZNC 1.8.2+deb3.1 - https://znc.in -> This is on Debian 12
    # ZNC 1.8.2+deb3.1+deb12u1 - https://znc.in -> Obviously also on Debian 12
    # nb: The +deb banner (which is using something like +deb1~bpo8) often doesn't match directly to the OS
    # so evaluate the ZNC banners before the more generic ones below.
    if( "ZNC" >< banner && ( "~bpo" >< banner || "+deb" >< banner ) ) {
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      if( "~bpo7" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "~bpo8" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "1.6.5+deb1" >< banner || "~bpo9" >< banner || banner =~ "\+deb[0-9.]+\+deb9" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "1.7.2+deb3" >< banner || "~bpo10" >< banner || banner =~ "\+deb[0-9.]+\+deb10" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "1.8.2+deb2+b1" >< banner || "~bpo11" >< banner || banner =~ "\+deb[0-9.]+\+deb11" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "1.8.2+deb3.1" >< banner || "~bpo12" >< banner || banner =~ "\+deb[0-9.]+\+deb12" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-8+etch16 mod_perl/2.0.2 Perl/v5.8.8
    # nb: Basically those should be covered by the previous banner for Apache but there might be other banners for different products.
    # nb: Keep in sync with the PHP banner in check_php_banner()
    if( banner =~ "[+\-~.]bookworm" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]bullseye" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]buster" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]stretch" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]jessie" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]wheezy" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]squeeze" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]lenny" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]etch" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]sarge" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]woody" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]potato" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]slink" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]hamm" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]bo[0-9 ]+" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]rex[0-9 ]+" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( banner =~ "[+\-~.]buzz" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)" ) {

      # nb: The order matters in case of backports which might have something like +deb9~bpo8
      # nb: Keep in sync with the PHP banner in check_php_banner()
      # ~dotdeb+squeeze
      # +deb6
      # ~deb6
      # ~bpo6
      # ~dotdeb+8
      # PHP/5.2.0-8+etch16
      # PHP/5.3.24-1~dotdeb.0
      # PHP/5.3.9-1~dotdeb.2
      # X-Powered-By: PHP/7.3.9-1~deb10u1
      # X-Powered-By: PHP/5.4.45-0+deb7u12
      # X-Powered-By: PHP/7.0.33-7+0~20190503101027.13+stretch~1.gbp26f991
      # X-Powered-By: PHP/7.2.22-1+0~20190902.26+debian9~1.gbpd64eb7
      if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(4|etch)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(5|lenny)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(6|squeeze)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(7|wheezy)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(8|jessie)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(9|stretch)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(10|buster)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(11|bullseye)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( banner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(12|bookworm)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    if( banner =~ "\(Debian\)" || banner =~ "\(Debian GNU/Linux\)" || "devel-debian" >< banner || "~dotdeb+" >< banner || banner =~ "\(Raspbian\)" ) {
      os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "\(Gentoo\)" || banner =~ "\(Gentoo Linux\)" || "-gentoo" >< banner ) {
      os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "\(Linux/SUSE\)" || banner =~ "/SuSE\)" ) {
      os_register_and_report( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "\(Arch Linux\)" ) {
      os_register_and_report( os:"Arch Linux", cpe:"cpe:/o:archlinux:arch_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "\(CentOS\)" ) {
      if( "Apache/2.4.37 (CentOS)" >< banner ) { # http://mirror.centos.org/centos/8/AppStream/x86_64/os/Packages/
        os_register_and_report( os:"CentOS", version:"8", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.6 (CentOS)" >< banner ) { # http://mirror.centos.org/centos/7/os/x86_64/Packages/
        os_register_and_report( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.2.15 (CentOS)" >< banner ) { # http://mirror.centos.org/centos/6/os/x86_64/Packages/
        os_register_and_report( os:"CentOS", version:"6", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.2.3 (CentOS)" >< banner ) { # http://vault.centos.org/5.0/os/x86_64/CentOS/
        os_register_and_report( os:"CentOS", version:"5", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.0.52 (CentOS)" >< banner ) { # http://vault.centos.org/4.0/os/x86_64/CentOS/RPMS/
        os_register_and_report( os:"CentOS", version:"4", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.0.46 (CentOS)" >< banner ) { # http://vault.centos.org/3.9/os/x86_64/RedHat/RPMS/
        os_register_and_report( os:"CentOS", version:"3", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # e.g.:
    # Server: Apache/2.4.37 (AlmaLinux)
    # Server: Apache/2.4.51 (AlmaLinux) OpenSSL/3.0.1
    # Server: Apache/2.4.53 (AlmaLinux) OpenSSL/3.0.1
    if( " (AlmaLinux)" >< banner ) {

      # https://repo.almalinux.org/almalinux/8.7/AppStream/x86_64/os/Packages/
      # https://repo.almalinux.org/almalinux/8.6/AppStream/x86_64/os/Packages/
      # nb: Both had the httpd-2.4.37 package so using the later one
      if( "Apache/2.4.37 (AlmaLinux)" >< banner )
        os_register_and_report( os:"Alma Linux", version:"8.7", cpe:"cpe:/o:almalinux:almalinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # https://repo.almalinux.org/almalinux/9.0/AppStream/x86_64/os/Packages/
      else if( "Apache/2.4.51 (AlmaLinux)" >< banner )
        os_register_and_report( os:"Alma Linux", version:"9.0", cpe:"cpe:/o:almalinux:almalinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # https://repo.almalinux.org/almalinux/9.1/AppStream/x86_64/os/Packages/
      else if( "Apache/2.4.53 (AlmaLinux)" >< banner )
        os_register_and_report( os:"Alma Linux", version:"9.1", cpe:"cpe:/o:almalinux:almalinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      else
        os_register_and_report( os:"Alma Linux", cpe:"cpe:/o:almalinux:almalinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      return;
    }

    # e.g.:
    # Server: Apache/2.4.51 (Rocky Linux)
    # Server: Apache/2.4.53 (Rocky Linux) OpenSSL/3.0.1
    # Server: Apache/2.4.37 (rocky) OpenSSL/1.1.1k mod_jk/1.2.48
    # Server: Apache/2.4.37 (rocky) OpenSSL/1.1.1k
    # nb:
    # - Seems they have switched from (rocky) to (Rocky Linux) in between 8.x and 9.x
    # - Because "rocky" might catch a little bit "too" much we're using a more strict (case
    #   sensitive) check here
    # - Similar to Alma Linux the httpd- packages are included in the "AppStream" repos and not in
    #   the "BaseOS" ones like seen on e.g. CentOS
    # - Older releases are moved into a separate "vault" repository so the link below might change
    if( egrep( string:banner, pattern:" \((Rocky Linux|rocky)\)", icase:FALSE ) ) {

      # https://dl.rockylinux.org/vault/rocky/8.3/AppStream/x86_64/os/Packages/
      # https://dl.rockylinux.org/vault/rocky/8.4/AppStream/x86_64/os/Packages/
      # https://dl.rockylinux.org/vault/rocky/8.5/AppStream/x86_64/os/Packages/h/
      # https://dl.rockylinux.org/vault/rocky/8.6/AppStream/x86_64/os/Packages/h/
      # https://download.rockylinux.org/pub/rocky/8.7/AppStream/x86_64/os/Packages/h/
      # nb: All had the httpd-2.4.37 packages so using the most recent one
      if( "Apache/2.4.37 (rocky)" >< banner )
        os_register_and_report( os:"Rocky Linux", version:"8.7", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # https://dl.rockylinux.org/vault/rocky/9.0/AppStream/x86_64/os/Packages/h/
      else if( "Apache/2.4.51 (Rocky Linux)" >< banner )
        os_register_and_report( os:"Rocky Linux", version:"9.0", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # https://download.rockylinux.org/pub/rocky/9.1/AppStream/x86_64/os/Packages/h/
      else if( "Apache/2.4.53 (Rocky Linux)" >< banner )
        os_register_and_report( os:"Rocky Linux", version:"9.1", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      else
        os_register_and_report( os:"Rocky Linux", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      return;
    }

    # nb: Keep the PHP/ banner in sync with the one of check_php_banner()
    if( banner =~ "\(Ubuntu\)" || ( "PHP/" >< banner && "ubuntu" >< banner ) ) {
      # Server: Apache/2.4.38 (Ubuntu) PHP/7.2.17-0ubuntu0.19.04.1
      # Server: Apache/2.4.41 (Ubuntu) PHP/7.3.11-0ubuntu0.19.10.1
      if( "Apache/2.4.58 (Ubuntu)" >< banner ) { # n.b. Missing ubuntu identifier in PHP banner currently only PHP/8.3.6
        os_register_and_report( os:"Ubuntu", version:"24.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.57 (Ubuntu)" >< banner || "PHP/8.2.10-2ubuntu2.2" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"23.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.55 (Ubuntu)" >< banner || "PHP/8.1.12-1ubuntu4" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"23.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.54 (Ubuntu)" >< banner || "PHP/8.1.7-1ubuntu3.1" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"22.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.52 (Ubuntu)" >< banner || "PHP/8.1.2-1ubuntu2.9" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"22.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.48 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"21.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.46 (Ubuntu)" >< banner ) { # nb: 21.04 and 20.10 had both Apache 2.4.46 so registering only 21.04 in the CPE.
        os_register_and_report( os:"Ubuntu", version:"20.10 or 21.04", cpe:"cpe:/o:canonical:ubuntu_linux:21.04", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
      } else if( "Apache/2.4.41 (Ubuntu)" >< banner ) { # nb: 20.04 and 19.10 had both Apache 2.4.41 so registering only 20.04 in the CPE.
        os_register_and_report( os:"Ubuntu", version:"19.10 or 20.04", cpe:"cpe:/o:canonical:ubuntu_linux:20.04", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
      } else if( "ubuntu0.20.04" >< banner || "nginx/1.17.10 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "ubuntu0.19.10" >< banner || "nginx/1.16.1 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.38 (Ubuntu)" >< banner || "ubuntu0.19.04" >< banner || "nginx/1.15.9 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.34 (Ubuntu)" >< banner || "PHP/7.2.10-0ubuntu1" >< banner || "nginx/1.15.5 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.4.29 (Ubuntu)" >< banner || "PHP/7.2.3-1ubuntu1" >< banner || "nginx/1.14.0 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.2.8 (Ubuntu)" >< banner || "PHP/5.2.4-2ubuntu5.10" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "nginx/1.12.1 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "nginx/1.10.3 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "nginx/1.4.6 (Ubuntu)" >< banner ) {
        os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    if( "(Red Hat Enterprise Linux)" >< banner ) {
      os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "(Red Hat)" >< banner || "(Red-Hat/Linux)" >< banner ) {
      # nb: Doubled space is expected...
      if( "Apache/1.3.23 (Unix)  (Red-Hat/Linux)" >< banner ) {
        # http://vault.centos.org/2.1/source/i386/SRPMS/ -> apache-1.3.23-10.src.rpm
        # TODO: Redhat version currently unknown, CentOS release taken from the src rpm above.
        os_register_and_report( os:"CentOS", version:"2", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    if( "(Fedora)" >< banner ) {
      os_register_and_report( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "(Oracle)" >< banner ) {
      os_register_and_report( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( banner =~ "\(Unix\)" ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "mini-http" >< banner && "(unix)" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "(Univention)" >< banner ) {
      os_register_and_report( os:"Univention Corporate Server", cpe:"cpe:/o:univention:univention_corporate_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.1mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
    # Server: Apache-AdvancedExtranetServer/2.0.53 (Mandrakelinux/PREFORK-9mdk) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/4.3.10 mod_perl/1.999.21 Perl/v5.8.6
    if( banner =~ "\(Mandrake ?[Ll]inux" ) {
      os_register_and_report( os:"Mandrake", cpe:"cpe:/o:mandrakesoft:mandrake_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Nginx on Linux Debian" >< banner ) {
      os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Nginx centOS" >< banner ) {
      os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Nginx (OpenBSD)" >< banner || ( "Lighttpd" >< banner && "OpenBSD" >< banner ) ) {
      os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Proxmox Virtual Environment (VE, PVE) is only running on Debian
    if( egrep( pattern:"^Server\s*:\s*pve-api-daemon", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # SERVER: POSIX, UPnP/1.0, Intel MicroStack/1.0.2126
    # Server: POSIX, UPnP/1.0, Intel MicroStack/1.0.2777
    if( "server: posix, upnp/1.0, intel microstack" >< tolower( banner ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix-like OS. Keep down below to catch more detailed OS infos above first.
    # e.g. Server: nginx + Phusion Passenger 5.1.12
    # Server: nginx/1.8.1 + Phusion Passenger 5.0.27
    # Server: Apache/2.4.18 (Ubuntu) OpenSSL/1.0.2g SVN/1.9.3 Phusion_Passenger/5.0.27 mod_perl/2.0.9 Perl/v5.22.1
    if( banner =~ "^Server: .* Phusion[ _]Passenger" ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: IceWarp WebSrv/3.1
    # Server: IceWarp/11.4.6.0 RHEL7 x64
    # Server: IceWarp/11.4.6.0 UBUNTU1404 x64
    # Server: IceWarp/11.4.5.0 x64
    if( egrep( pattern:"^Server\s*:\s*IceWarp", string:banner, icase:TRUE ) ) {
      if( os_info = eregmatch( pattern:"[Ss]erver\s*:\s*IceWarp( WebSrv)?/([0-9.]+) ([^ ]+) ([^ ]+)", string:banner, icase:FALSE ) ) {
        if( "RHEL" >< os_info[3] ) {
          version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            os_register_and_report( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        } else if( "DEB" >< os_info[3] ) {
          version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        } else if( "UBUNTU" >< os_info[3] ) {
          version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
            os_register_and_report( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        }
        # nb: No return at this level here as we want to report an unknown OS later...
      } else {
        return; # No OS info so just skip this IceWarp banner...
      }
    }

    # CUPS is running only on iOS, iPadOS, macOS other UNIX-like operating systems and Linux...
    if( egrep( pattern:"^[Ss]erver\s*:\s*CUPS/", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # Some CUPS deployments servers might provide additional OS pattern, report an unknown OS as well
      # if none of the generic known pattern below is matching...
      if( ! egrep( pattern:"^[Ss]erver\s*:\s*CUPS/[0-9.]+ IPP/[0-9.]+$", string:banner ) &&
          ! egrep( pattern:"^[Ss]erver\s*:\s*CUPS/[0-9.]+$", string:banner ) ) {
        os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
      }
      return;
    }

    # PowerDNS webserver is only running on Unix-like OS variants
    # https://doc.powerdns.com/md/authoritative/settings/#webserver
    # https://doc.powerdns.com/md/httpapi/README/
    # e.g. Server: PowerDNS/4.0.3
    if( egrep( pattern:"^[Ss]erver\s*:\s*PowerDNS", string:banner ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      if( egrep( pattern:"^[Ss]erver\s*:\s*PowerDNS/([0-9.]+)$", string:banner ) ) {
        # nb: Only return if there are no additional info within the banner so
        # that we're reporting an unknown OS later in other cases...
        return;
      }
    }

    # Tinyproxy is only running on Unix-like OS variants according to: https://tinyproxy.github.io/
    # e.g.:
    # Server: tinyproxy/1.8.4
    # Server: tinyproxy/1.11.0-rc1-46-git-d3d8943
    #
    if( egrep( pattern:"^[Ss]erver\s*:\s*tinyproxy", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # nb: Only return if there is no additional info within the banner so that we're reporting an
      # unknown OS later in other cases...
      if( egrep( pattern:"^[Ss]erver\s*:\s*tinyproxy/([0-9.]+)$", string:banner, icase:FALSE ) ||
          "-git-" >< banner ) {
        return;
      }
    }

    # nb: Keep at the bottom to catch all the more detailed patterns above...
    # Server: Compal Broadband Networks, Inc/Linux/2.6.39.3 UPnP/1.1 MiniUPnPd/1.7
    # SERVER: Linux/3.0.8, UPnP/1.0, Portable SDK for UPnP devices/1.6.6
    # SERVER: LINUX-2.6 UPnP/1.0 MiniUPnPd/1.5
    # Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10WW
    if( egrep( pattern:"^Server\s*:.*Linux", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server\s*:.*Linux(/|\-)([0-9.x]+)", string:banner, icase:TRUE );
      if( ! isnull( version[2] ) ) {
        os_register_and_report( os:"Linux", version:version[2], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # e.g.:
    # Server: Apache/2.0.63FTF (NETWARE) mod_jk/1.2.23 PHP/5.0.5
    # Server: Apache/2.0.59 (NETWARE) mod_jk/1.2.21
    # Server: NetWare HTTP Stack
    if( banner =~ "Server: (NetWare HTTP Stack|Apache.+\(NETWARE\))" ) {
      os_register_and_report( os:"Novell NetWare / Open Enterprise Server (OES)", cpe:"cpe:/o:novell:open_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*(NetApp|Data ONTAP)", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.: Server: ioLogik Web Server/1.0
    # nb: More detailed OS Detection covered in gb_moxa_iologik_devices_consolidation.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*ioLogik Web Server", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Moxa ioLogik Firmware", cpe:"cpe:/o:moxa:iologik_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Seems to run on embedded Linux/Unix on Devices like:
    # Enterasys RBT-8200
    # 3Com WX2200 WAP
    # Juniper Trapeze
    # e.g.
    # Server: TreeNeWS/0.0.1
    # Server: TreeNeWS/ETt
    # Server: TreeNeWS/je
    # Server: TreeNeWS/Xade_
    if( egrep( pattern:"^[Ss]erver\s*:\s*TreeNeWS", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: More detailed OS Detection covered in gsf/gb_ewon_flexy_cosy_http_detect.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*eWON", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"eWON Firmware", cpe:"cpe:/o:ewon:ewon_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: xxxxxxxx-xxxxx
    # nb: On /remote/login?lang=en the service is also setting empty SVPNCOOKIE and SVPNNETWORKCOOKIE cookies.
    if( egrep( pattern:"^[Ss]erver\s*:\s*xxxxxxxx-xxxxx", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: ClearSCADA/6.74.5192.1
    if( egrep( pattern:"^[Ss]erver\s*:\s*ClearSCADA", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: LANCOM
    # Server: LANCOM 1721 VPN (Annex B) 7.58.0045 / 14.11.2008
    # nb: More detailed detection in gb_lancom_devices_http_detect.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*LANCOM", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"LANCOM Firmware", cpe:"cpe:/o:lancom:lancom_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( egrep( pattern:"^[Ss]erver\s*:\s*(HUAWEI|HuaWei|AR|WLAN)", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe:"cpe:/o:huawei:vrp_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Grandstream GXP1400
    # Server: Grandstream GXP2010 1.1.6.27
    # Server: Grandstream GXP1165
    # Server: Grandstream GXP280 1.2.5.2
    #
    # nb: More detailed detection in gb_grandstream_gxp_http_detect.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*Grandstream GXP", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Grandstream GXP Firmware", cpe:"cpe:/o:grandstream:gxp_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: DrayTek/Vigor2130 UPnP/1.0 miniupnpd/1.0
    # nb: More detailed detection in gb_draytek_vigor_http_detect.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*DrayTek/Vigor", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"DrayTek Vigor Firmware", cpe:"cpe:/o:draytek:vigor_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: Only runs on these OS variants according to https://control-webpanel.com/installation-instructions#step2
    if( egrep( pattern:"^[Ss]erver\s*:\s*cwpsrv", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      os_register_and_report( os:"Rocky Linux", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      os_register_and_report( os:"Alma Linux", cpe:"cpe:/o:almalinux:almalinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      os_register_and_report( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: xxxx
    if( egrep( pattern:"^[Ss]erver\s*:\s*xxxx$", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Sophos SFOS", cpe:"cpe:/o:sophos:sfos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: lighttpd/1.4.32-SATO_r17
    # Server: lighttpd/1.4.32-SATO_r17-3-gcadb4bb
    if( egrep( pattern:"^[Ss]erver\s*:\s*lighttpd/.+SATO", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"SATO Printer Firmware", cpe:"cpe:/o:sato:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Symantec Endpoint Protection Manager
    # Server: SEPM
    if( egrep( pattern:"^Server\s*:\s*(SEPM|Symantec Endpoint Protection Manager)", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: Contiki/2.4
    # nb: More detailed detection in gsf/gb_contiki_os_http_detect.nasl
    if( egrep( pattern:"^Server\s*:\s*Contiki/", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Contiki OS", cpe:"cpe:/o:contiki-os:contiki", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Ethernut 5.2.2.0
    # nb: More detailed detection in gsf/gb_ethernut_http_detect.nasl
    if( egrep( pattern:"^Server\s*:\s*Ethernut", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Ethernut (Nut/OS)", cpe:"cpe:/o:ethernut:nut_os", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Loxone 6.2.12.4
    # nb: More detailed OS detection in gb_loxone_miniserver_consolidation.nasl
    if( egrep( pattern:"^Server\s*:\s*Loxone", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Loxone Miniserver Firmware", cpe:"cpe:/o:loxone:miniserver_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: CirCarLife Scada v4.2.1
    # nb: More detailed OS detection in gsf/gb_circontrol_circarlife_http_detect.nasl
    if( egrep( pattern:"^Server\s*:\s*CirCarLife Scada", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Circontrol CirCarLife Firmware", cpe:"cpe:/o:circontrol:circarlife_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # From the vendor homepage: NexusDB V3 is supported on any windows version from Win XP onwards
    if( egrep( string:banner, pattern:"^Server\s*:\s*NexusDB WebServer", icase:TRUE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: TP-LINK HTTPD/1.0
    # e.g. TP-Link TL-WA850RE V6
    if( egrep( string:banner, pattern:"^Server\s*:\s*TP-LINK HTTPD", icase:TRUE ) ) {
      os_register_and_report( os:"TP-Link Unknown Device Firmware", cpe:"cpe:/o:tp-link:unknown_device_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: Frontier Silicon based platform, most likely some embedded Linux
    if( egrep( string:banner, pattern:"^Server\s*:\s*FSL DLNADOC", icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: PsiOcppApp (PowerStudio integration Open Charge Point Protocol Application), most likely some embedded Linux
    if( egrep( string:banner, pattern:"^Server\s*:\s*PsiOcppApp", icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Raption v5.12.0
    # nb: More detailed OS detection in gsf/gb_circontrol_raption_http_detect.nasl
    if( egrep( string:banner, pattern:"^Server\s*:\s*Raption", icase:TRUE ) ) {
      os_register_and_report( os:"Circontrol Raption Firmware", cpe:"cpe:/o:circontrol:raption_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: SonicWALL SSL-VPN Web Server
    # or just:
    # Server: SonicWALL
    # and maybe also:
    # Server: SonicWall
    # Might run on SMA 100 series or similar so just use a generic CPE
    # More detailed OS detection in VTs like e.g. gb_dell_sonicwall_sma_sra_consolidation.nasl
    if( egrep( string:banner, pattern:"^Server\s*:\s*SonicWALL", icase:TRUE ) ) {
      os_register_and_report( os:"SonicWall SMA / SRA Firmware", cpe:"cpe:/o:sonicwall:unknown_device_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: SMA/12.4
    # More detailed OS detection in VTs like e.g. gb_dell_sonicwall_sma_sra_consolidation.nasl
    if( egrep( string:banner, pattern:"^[Ss]erver\s*:\s*SMA(/[0-9.]+)?$", icase:FALSE ) ) {
      os_register_and_report( os:"SonicWall SMA Firmware", cpe:"cpe:/o:sonicwall:sma_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # More detailed OS detection in VTs like e.g. gb_dell_sonicwall_sma_sra_consolidation.nasl
    if( egrep( string:banner, pattern:"^[Ss]erver\s*:\s*SRA(/[0-9.]+)?$", icase:FALSE ) ) {
      os_register_and_report( os:"SonicWall SRA Firmware", cpe:"cpe:/o:sonicwall:sra_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Various HP printers, e.g.:
    # Server: HP HTTP Server; HP DeskJet 3630 series - K4T99B; Serial Number: <redacted>; Built:Sat May 16, 2020 06:59:45AM {SWP1FN2020CR}
    # Server: HP HTTP Server; HP Deskjet 3540 series - A9T81B; Serial Number: <redacted>; Built:Mon Jun 15, 2020 09:27:46AM {MLM1FN2025AR}
    # Server: HP HTTP Server; HP Officejet Pro 8600 - CM750A; Serial Number: <redacted>; Coulomb_kaiser_pp Built:Tue Jul 17, 2018 11:17:20AM {CKP1CN1829AR, ASIC id 0x00320104}
    # Server: HP HTTP Server; HP OfficeJet Pro 8730 - D9L20A; Serial Number: <redacted>; Built: Wed Jan 27, 2021 08:26:43PM {WEBPDLPP1N001.2105G.00}
    # Server: HP HTTP Server; HP ENVY 4500 series - A9T80A; Serial Number: <redacted>; Built:Mon Jun 15, 2020 09:29:10AM {MKM1FN2025AR}
    # Server: HP HTTP Server; HP HP Officejet Pro 8630 - A7F66A; Serial Number: <redacted>; Built:Wed May 27, 2020 06:44:32AM {FDP1CN2022AR}
    if( egrep( string:banner, pattern:"^Server\s*:\s*HP HTTP Server; HP", icase:TRUE ) ) {
      os_register_and_report( os:"HP Printer Firmware", cpe:"cpe:/o:hp:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Some Samsung printers seems to use the HP HTTP server, e.g.:
    # Server: HP HTTP Server; Samsung SL-J1560W Series - 2NG32; Serial Number: <redacted>; Built:Fri Feb 15, 2019 10:23:26AM {KEP1FN1907BR}
    # Server: HP HTTP Server; Samsung  SL-J2160W Series - W7V15A; Serial Number: <redacted>; Built:Tue May 19, 2020 03:03:27PM {NBP1CN2021AR}
    # nb: Two spaces above have been seen like this.
    if( egrep( string:banner, pattern:"^Server\s*:\s*HP HTTP Server; Samsung", icase:TRUE ) ) {
      os_register_and_report( os:"Samsung Printer Firmware", cpe:"cpe:/o:samsung:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: MSA/1.0
    # nb: MagicFlow MSA Gateway. Most likely running some embedded Linux
    if( egrep( string:banner, pattern:"^[Ss]erver\s*:\s*MSA(/[0-9.]+)?$", icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: Start HTTP-Server/1.1
    if( egrep( string:banner, pattern:"^Server\s*:\s*Start HTTP\-Server", icase:TRUE ) ) {
      os_register_and_report( os:"Ruije Networks Device Firmware", cpe:"cpe:/o:ruijie_networks:device_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb:
    # - Collabora / LibreOffice Online
    # - Since some versions released in around November 2024 the version is now getting dropped by
    #   default (still can be optionally enabled in the coolwsd.conf) or the HTTP header is
    #   completely gone (Only the Server: string is there)
    # - See User-Agent part below for more background info
    #
    # e.g.:
    #
    # Server: COOLWSD HTTP Server 21.11.0.3snapshot
    # Server: COOLWSD HTTP Server 21.11.0.3
    # Server: COOLWSD HTTP Server
    #
    if( egrep( string:banner, pattern:"^Server\s*:\s*[CL]OOLWSD (WOPI|HTTP) Server", icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: cPanel
    # Server: Apache/2.4.48 (cPanel) OpenSSL/1.1.1k mod_bwlimited/1.4
    # From Wikipedia:
    # The latest cPanel & WHM version supports installation on CentOS, Red Hat Enterprise Linux (RHEL), and CloudLinux OS.[4] cPanel 11.30 is the last major version to support FreeBSD.
    if( egrep( string:banner, pattern:"^Server\s*:\s*(cPanel|Apache.+\(cPanel\))", icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # server: StorageGRID/11.5.0.4
    # Server: StorageGRID/11.4.0.2
    # Server: StorageGRID/11.3.0.12
    # Software seems to run on Debian, Ubuntu, CentOS and RHEL
    if( egrep( string:banner, pattern:"^Server\s*:\s*StorageGRID", icase:TRUE ) ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # SERVER: EPSON_Linux UPnP/1.0 Epson UPnP SDK/1.0
    # Server: EPSON HTTP Server
    # Server: EPSON-HTTP/1.0
    # nb: Note that the "Epson UPnP SDK" shouldn't use a "^"
    # nb: More detailed OS detection / extraction in gb_epson_printer_http_detect.nasl
    # nb: Keep in sync with gb_epson_printer_http_detect.nasl and dont_print_on_printers.nasl
    if( egrep( string:banner, pattern:"(^SERVER\s*:\s*(EPSON_Linux|EPSON HTTP Server|EPSON-HTTP)|Epson UPnP SDK)", icase:TRUE ) ) {
      os_register_and_report( os:"Epson Printer Firmware", cpe:"cpe:/o:epson:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: KS_HTTP/1.0
    # Server: CANON HTTP Server
    # Server: Catwalk
    # nb: More detailed OS detection / extraction in gb_canon_printer_http_detect.nasl
    # nb: Keep in sync with gb_canon_printer_http_detect.nasl and dont_print_on_printers.nasl
    if( egrep( string:banner, pattern:"^Server\s*:\s*(KS_HTTP|CANON HTTP Server|Catwalk)", icase:TRUE ) ) {
      os_register_and_report( os:"Canon Printer Firmware", cpe:"cpe:/o:canon:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: KM-MFP-http/V0.0.1
    # nb: Keep in sync with gb_kyocera_printer_http_detect.nasl and dont_print_on_printers.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*KM-MFP-http", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Kyocera Printer Firmware", cpe:"cpe:/o:kyocera:printer_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: A8000
    # nb: More detailed detection in gsf/gb_siemens_sicam_a8000_http_detect.nasl
    if( egrep( pattern:"^[Ss]erver\s*:\s*A8000", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Siemens SICAM A8000 Firmware", cpe:"cpe:/o:siemens:sicam_a8000_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: RStudio Connect v2022.02.3
    # nb: See gsf/gb_rstudio_connect_http_detect.nasl as well
    if( egrep( pattern:"^[Ss]erver\s*:\s*RStudio Connect", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: iSpy
    if( egrep( pattern:"^[Ss]erver\s*:\s*iSpy", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: Barracuda CloudGen Firewall
    if( "Barracuda CloudGen Firewall" >< banner ) {
      os_register_and_report( os:"Barracuda CloudGen Firewall Firmware", cpe:"cpe:/o:barracuda:cloudgen_firewall_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: gunicorn/19.8.1
    if( egrep( pattern:"^Server\s*:\s*gunicorn", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # From https://www.meinbergglobal.com/english/products/ntp-time-server.htm#prgchar:
    # Operating System of the SBC: Linux with nano kernel (incl. PPSkit)
    # nb: More detailed detection covered in gb_meinberg_lantime_consolidation.nasl
    # Only:
    # Server: LANTIME
    if( egrep( pattern:"^[Ss]erver\s*:\s*LANTIME", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Meinberg LANTIME Firmware", cpe:"cpe:/o:meinbergglobal:lantime_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: See gsf/2023/huawei/gb_huawei_lfi_vuln_apr23_active.nasl
    if( egrep( pattern:"^Server\s*:\s*Huawei Auth-Http Server", string:banner, icase:TRUE ) ) {
      os_register_and_report( os:"Huawei Unknown Device Firmware", cpe:"cpe:/o:huawei:unknown_device_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: MailEnable-HTTP/5.0
    if( egrep( pattern:"^[Ss]erver\s*:\s*MailEnable-HTTP", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # e.g.:
    # Server: AAS/<someversion>
    if( egrep( pattern:"^[Ss]erver\s*:\s*AAS", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # e.g.:
    # Server: Titan FTP Server/<someversion>
    if( egrep( pattern:"^[Ss]erver\s*:\s*Titan FTP Server", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # e.g.:
    # Server: Cornerstone MFT Server/<someversion>
    if( egrep( pattern:"^[Ss]erver\s*:\s*Cornerstone MFT Server", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # e.g.:
    # Server: Polycom VVX Telephone HTTPd
    # Server: Poly CCX Telephone HTTPd
    if( egrep( pattern:"^[Ss]erver\s*:\s*Poly(com)? .*Telephone HTTPd", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Polycom Unified Communications Software", cpe:"cpe:/o:polycom:unified_communications_software", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: CNIX HTTP Server 1.0
    if( egrep( pattern:"^[Ss]erver\s*:\s*CNIX HTTP Server", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Siemens LOGO! Firmware", cpe:"cpe:/o:siemens:logo%21_8_bm_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Seems to run only on Unix-like OS, e.g.:
    # Server: rspamd/1.8.1
    # Server: rspamd/1.9.4
    # Server: rspamd/3.7.3
    if( egrep( pattern:"^[Ss]erver\s*:\s*rspamd", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Seems to run only on Linux, e.g.:
    # Server: Flowmon
    if( egrep( pattern:"^[Ss]erver\s*:\s*Flowmon", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Seems to run only on Linux according to https://github.com/monkey/monkey:
    # > Monkey is a fast and lightweight Web Server for Linux
    #
    # e.g.:
    # Server: Monkey/1.7.0
    # Server: Monkey/1.7.2
    if( egrep( pattern:"^[Ss]erver\s*:\s*Monkey", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: AWS (Ada Web Server)
    if( egrep( pattern:"^[Ss]erver\s*:\s*AWS \(Ada Web Server\)", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.:
    # Server: Cleo Harmony/5.8.0.21 (Linux)
    # Server: Cleo VLTrader/5.8.0.24 (Linux)
    # Server: Cleo LexiCom/5.8.0.21 (Linux)
    # Server: Cleo LexiCom/5.6.1.0 (Windows 10)
    # Server: Cleo LexiCom/5.7.0.0 (Windows Server 2019)
    # Server: Cleo Harmony/5.8.0.21 (Windows Server 2016)
    # Server: Cleo LexiCom/5.0 (Windows Server 2008 R2)
    # Server: Cleo LexiCom/4.5 (Windows Server 2008 R2)
    # Server: Cleo LexiCom/5.6.2.0 (Windows 2003)
    # Server: Cleo VLTrader/5.8.0.21 (Windows Server 2012 R2)
    # Server: Cleo LexiCom/4.4 (Windows XP)
    # Server: Cleo LexiCom/4.5 (Windows NT (unknown))
    # Server: Cleo VLTrader/5.8.0.21 (Windows Server 2022)
    # Server: Cleo LexiCom/5.6.1.0 (Windows 7)
    #
    # nb: Only the known ones from above have been added here for now.
    if( banner =~ "[Ss]erver\s*:\s*Cleo [^(]+\([^)]+\)" ) {

      if( "(Windows Server 2022)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2022", cpe:"cpe:/o:microsoft:windows_server_2022", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows Server 2019)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2019", cpe:"cpe:/o:microsoft:windows_server_2019", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows Server 2016)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows 10)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows Server 2012 R2)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows Server 2008 R2)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows 7)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows 2003)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      if( "(Windows XP)" >< banner ) {
        os_register_and_report( os:"Microsoft Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      # nb: Just register all other (unknown) ones as Windows for now
      if( "(Windows" >< banner ) {
        os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        return;
      }

      # nb: This is usually already covered in one part above but has left in here on purpose
      if( "(Linux)" >< banner ) {
        os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    # nb: Seems to run only on FreeBSD, e.g.:
    # Server: OPNsense
    if( egrep( pattern:"^[Ss]erver\s*:\s*OPNsense", string:banner, icase:FALSE ) ) {
      os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
  }

  return;
}

function check_php_banner( port, host ) {

  local_var port, host;
  local_var checkFiles, dir, phpFilesList, count, phpFile, checkFile, banner, phpBanner, phpscriptsUrls, phpscriptsUrl, _phpBanner, banner_type;

  checkFiles = make_list();

  foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {
    if( dir == "/" ) dir = "";
    checkFiles = make_list( checkFiles, dir + "/", dir + "/index.php" );
  }

  phpFilesList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
  if( phpFilesList && is_array( phpFilesList ) ) {
    count = 0;
    foreach phpFile( phpFilesList ) {
      count++;
      checkFiles = make_list_unique( checkFiles, phpFile );
      if( count >= 10 ) break; # TBD: Should be enough files to check, maybe we could even lower this to 5...
    }
  }

  foreach checkFile( checkFiles ) {

    banner = http_get_remote_headers( port:port, file:checkFile );

    phpBanner = egrep( pattern:"^X-Powered-By\s*:\s*PHP/.+$", string:banner, icase:TRUE );
    if( ! phpBanner )
      continue;

    phpBanner = chomp( phpBanner );

    # Too generic, e.g.:
    # X-Powered-By: PHP/7.3.4-2
    # X-Powered-By: PHP/7.3.4
    if( egrep( pattern:"^X-Powered-By\s*:\s*PHP/[0-9.]+(-[0-9.]+)?$", string:phpBanner ) ) {
      phpBanner = NULL;
      continue;
    }

    banner_type = "PHP Server banner";
    break;
  }

  if( ! phpBanner ) {
    # nb: Currently set by sw_apcu_info.nasl and gb_phpinfo_output_detect.nasl but could be extended by other PHP scripts providing such info
    phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
    if( phpscriptsUrls && is_array( phpscriptsUrls ) ) {
      foreach phpscriptsUrl( phpscriptsUrls ) {
        _phpBanner = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
        if( _phpBanner && _phpBanner =~ "[0-9.]+" ) {
          banner_type = "phpinfo()/ACP(u) output";
          phpBanner = _phpBanner;
          break; # TBD: Don't stop after the first hit? But that could report the very same PHP version if multiple scripts were found.
        }
      }
    }
  }

  if( phpBanner ) {

    # e.g. X-Powered-By: PHP/5.4.24-1+sury.org~lucid+1 or X-Powered-By: PHP/7.1.8-2+ubuntu14.04.1+deb.sury.org+4
    if( "sury.org" >< phpBanner ) {
      version = eregmatch( pattern:"\+ubuntu([0-9.]+)", string:phpBanner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Ubuntu versions. Still keep them in here as we can't know...
    if( "~warty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~hoary" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~breezy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~dapper" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~edgy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~feisty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~gutsy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~hardy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~intrepid" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~jaunty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~karmic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~lucid" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~maverick" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~natty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~oneiric" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~precise" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~quantal" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~raring" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~saucy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~trusty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~utopic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~vivid" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~wily" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~xenial" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~yakkety" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~zesty" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~artful" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~bionic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~cosmic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~disco" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~eoan" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~focal" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~groovy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"20.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~hirsute" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"21.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~impish" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"21.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~jammy" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"22.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~kinetic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"22.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~lunar" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"23.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~mantic" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"23.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~noble" >< phpBanner ) {
      os_register_and_report( os:"Ubuntu", version:"24.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # X-Powered-By: PHP/7.2.3-1ubuntu1
    #
    # nb: Newer PHP versions on Ubuntu doesn't use a "expose_php = On" but still trying to detect it here...
    #
    # TODO: Check and add banners of all Ubuntu versions. Take care of versions which
    # exists between multiple Ubuntu releases and register only the highest Ubuntu version.
    #
    # nb: Keep in sync with the PHP banner in check_http_banner()
    if( "ubuntu" >< phpBanner ) {
      # X-Powered-By: PHP/7.2.17-0ubuntu0.19.04.1
      # X-Powered-By: PHP/7.3.11-0ubuntu0.19.10.1
      if( "PHP/8.2.10-2ubuntu2.2" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"23.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/8.1.12-1ubuntu4" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"23.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/8.1.7-1ubuntu3.1" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"22.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/8.1.2-1ubuntu2.9" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"22.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "ubuntu0.20.04" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "ubuntu0.19.10" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "ubuntu0.19.04" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/7.2.10-0ubuntu1" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/7.2.3-1ubuntu1" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/5.2.4-2ubuntu5.10" >< phpBanner ) {
        os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # nb: The naming of the sury.org PHP banners have some special syntax like: PHP/7.1.7-1+0~20170711133844.5+jessie~1.gbp5284f4
    # nb: Keep in sync with the PHP banner in check_http_banner()
    if( phpBanner =~ "[+\-~.]bookworm" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]bullseye" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]buster" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]stretch" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]jessie" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]wheezy" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]squeeze" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]lenny" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]etch" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]sarge" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]woody" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]potato" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]slink" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]hamm" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]bo[0-9 ]+" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]rex[0-9 ]+" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( phpBanner =~ "[+\-~.]buzz" ) {
      os_register_and_report( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)" ) {

      # nb: The order matters in case of backports which might have something like +deb9~bpo8
      # nb: Keep in sync with the PHP banner in check_http_banner()
      # ~dotdeb+squeeze
      # +deb6
      # ~deb6
      # ~bpo6
      # ~dotdeb+8
      # PHP/5.2.0-8+etch16
      # PHP/5.3.24-1~dotdeb.0
      # PHP/5.3.9-1~dotdeb.2
      # PHP/5.6.15-1~dotdeb+7.1
      # X-Powered-By: PHP/7.3.9-1~deb10u1
      # X-Powered-By: PHP/5.4.45-0+deb7u12
      # X-Powered-By: PHP/7.0.33-7+0~20190503101027.13+stretch~1.gbp26f991
      # X-Powered-By: PHP/7.2.22-1+0~20190902.26+debian9~1.gbpd64eb7
      if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(4|etch)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(5|lenny)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(6|squeeze)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(7|wheezy)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(8|jessie)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(9|stretch)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(10|buster)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(11|bullseye)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( phpBanner =~ "[+\-~.](deb|dotdeb|bpo|debian)[+\-~.]?(12|bookworm)" ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }
    os_register_unknown_banner( banner:phpBanner, banner_type_name:banner_type, banner_type_short:"php_banner", port:port );
  }
  return;
}

function check_default_page( port ) {

  local_var port, buf, banner_type, check;

  buf = http_get_cache( item:"/", port:port );
  if( buf && ( buf =~ "^HTTP/1\.[01] 200" || buf =~ "^HTTP/1\.[01] 403" ) ) { # nb: Seems Oracle Linux is throwing a "forbidden" by default

    banner_type = "HTTP Server default page";

    # <title>Apache HTTP Server Test Page powered by CentOS</title>
    # <title>HTTP Server Test Page powered by: Rocky Linux</title>
    if( "<title>Test Page for the Apache HTTP Server" >< buf ||
        "<title>Apache HTTP Server Test Page" >< buf ||
        "<title>HTTP Server Test Page" >< buf ||
        "<title>Test Page for the Nginx HTTP Server" >< buf ) {

      check = "on Red Hat Enterprise Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by CentOS</title>";
      if( check >< buf ) {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on CentOS</title>";
      if( check >< buf ) {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora Core</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by Ubuntu</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by Debian</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Mageia</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Mageia", cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on EPEL</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Scientific Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Scientific Linux", cpe:"cpe:/o:scientificlinux:scientificlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on the Amazon Linux AMI</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on CloudLinux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"CloudLinux", cpe:"cpe:/o:cloudlinux:cloudlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on SLES Expanded Support Platform</title>";
      if( check >< buf ) {
        os_register_and_report( os:"SUSE Linux Enterprise Server", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on EulerOS Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Huawei EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on openEuler Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"openEuler", cpe:"cpe:/o:openatom:openeuler", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Oracle Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # Seen on e.g. Oracle Linux 7.4
      check = "powered by Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "Rocky Linux</title>";
      if( check >< buf ) {
        os_register_and_report( os:"Rocky Linux", cpe:"cpe:/o:rocky:rocky", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>(Test Page for the (Apache|Nginx) HTTP Server|(Apache )?HTTP Server Test Page) (powered by|on)[^<]+</title>" ) ) {
        os_register_unknown_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<TITLE>Welcome to Jetty" >< buf ) {

      check = "on Debian</TITLE>";

      if( check >< buf ) {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<TITLE>Welcome to Jetty.*on.*</TITLE>" ) ) {
        os_register_unknown_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<title>Welcome to nginx" >< buf ) {

      check = "on Debian!</title>";

      if( check >< buf ) {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Ubuntu!</title>";

      if( check >< buf ) {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora!</title>";

      if( check >< buf ) {
        os_register_and_report( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Slackware!</title>";

      if( check >< buf ) {
        os_register_and_report( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>Welcome to nginx on.*!</title>" ) ) {
        os_register_unknown_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<title>Apache2" >< buf && "Default Page: It works</title>" >< buf ) {

      check = "<title>Apache2 Debian Default Page";

      if( check >< buf ) {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "<title>Apache2 Ubuntu Default Page";

      if( check >< buf ) {
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "<title>Apache2 centos Default Page";

      if( check >< buf ) {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>Apache2 .* Default Page: It works</title>" ) ) {
        os_register_unknown_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( egrep( string:buf, pattern:"^\s*If you find a bug in this Lighttpd package, or in Lighttpd itself, please file a bug report on it\.", icase:FALSE ) ) {

      # This is a placeholder page installed by the Ubuntu release of the <a href="http://packages.ubuntu.com/lighttpd">Lighttpd server package.</a>
      # This is a placeholder page installed by the Debian release of the <a href="http://packages.debian.org/lighttpd">Lighttpd server package.</a>
      # This computer has installed the Debian GNU/Linux operating system, but it has nothing to do with the Debian Project
      # This computer has installed the Ubuntu operating system, but it has nothing to do with the Ubuntu Project.
      # nb: egrep() is used first so that the [^\r\n]+ is not accidentally matching "too much" (shouldn't happen but just to make sure...)
      pattern = '(installed by the ([^\r\n]+) release of the|has installed the ([^\r\n]+) operating system)';
      if( check = egrep( string:buf, pattern:pattern, icase:FALSE ) ) {

        has_os = eregmatch( string:check, pattern:pattern, icase:FALSE );
        if( has_os[2] || has_os[3] ) {

          if( "Ubuntu" >< has_os[2] || "Ubuntu" >< has_os[3] ) {
            os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:has_os[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
            return;
          } else if( "Debian" >< has_os[2] || "Debian" >< has_os[3] ) {
            os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:has_os[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
            return;
          }

          # nb: Only found Debian and Ubuntu so far but there might be more unknown so just report it
          # if we have found possible unknown ones...
          os_register_unknown_banner( banner:has_os[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
        }
      }
    }

    # nb:
    # - CUPS is running only on iOS, iPadOS, macOS other UNIX-like operating systems and Linux...
    # - When adding additional strings here make sure to also update the check in gb_cups_http_detect.nasl
    if( check = eregmatch( string:buf, pattern:"<TITLE>(Forbidden|Home|Not Found|Bad Request|Web Interface is Disabled) - CUPS.*</TITLE>", icase:TRUE ) ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
  }

  # TODO: There might be more of such default pages for other Distros...
  # But at least Ubuntu is using the index.nginx-debian.html as well.
  url = "/index.nginx-debian.html";
  buf = http_get_cache( item:url, port:port );
  if( buf && buf =~ "^HTTP/1\.[01] 200" && "<title>Welcome to nginx!</title>" >< buf ) {
    os_register_and_report( os:"Debian GNU/Linux or Ubuntu", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:http_report_vuln_url( port:port, url:url, url_only:TRUE ), desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  return;
}

function check_x_powered_by_banner( port, banner ) {

  local_var port, banner;
  local_var banner_type;

  if( ! banner )
    return;

  if( banner = egrep( pattern:"^X-Powered-By\s*:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    if( banner =~ "^X-Powered-By\s*:\s*$" )
      return;

    # Both covered by check_php_banner()
    # e.g. X-Powered-By: PHP/7.0.19 or X-Powered-By: PHP/7.0.19-1
    if( " PHP" >< banner || egrep( pattern:"^X-Powered-By\s*:\s*PHP/[0-9.]+(-[0-9]+)?$", string:banner, icase:TRUE ) )
      return;

    # Express Node.js Framework is supported on Windows, Linux/Unix etc.
    if( banner =~ "^X-Powered-By\s*:\s*Express$" )
      return;

    # Java based application, cross-platform.
    # e.g. X-Powered-By: Servlet/3.0
    if( egrep( pattern:"^X-Powered-By\s*:\s*Servlet/([0-9.]+)$", string:banner, icase:TRUE ) )
      return;

    # Cross-platform (Java), e.g.:
    # X-Powered-By: Undertow/1
    if( egrep( pattern:"^X-Powered-By\s*:\s*Undertow(/[0-9.]+)?$", string:banner, icase:TRUE ) )
      return;

    # Cross-platform (at least Windows, Linux and Mac OS X), e.g.:
    # X-Powered-By: ASP.NET
    if( banner == "X-Powered-By: ASP.NET" )
      return;

    banner_type = "X-Powered-By Server banner";

    # X-Powered-By: PleskWin
    if( "PleskWin" >< banner ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # X-Powered-By: PleskLin
    if( "PleskLin" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix-like OS.
    # e.g. X-Powered-By: Phusion Passenger Enterprise 5.1.12
    # X-Powered-By: Phusion Passenger 5.0.27
    if( "Phusion Passenger" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
    os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_x_powered_by_banner", port:port );
  }

  return;
}

# nb: Separate function as there are systems which had e.g.:
# X-Powered-By: ASP.NET
# X-Powered-By-Plesk: PleskWin
# and the check_x_powered_by_banner() had "returned" in that case
function check_x_powered_by_plesk_banner( port, banner ) {

  local_var port, banner;
  local_var banner_type;

  if( ! banner )
    return;

  if( banner = egrep( pattern:"^X-Powered-By-Plesk\s*:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    # X-Powered-By-Plesk:
    # X-Powered-By-Plesk: PleskWin
    # nb: Only seen the "PleskWin" so far but the PleskLin was also added just to be sure...
    if( banner =~ "^X-Powered-By-Plesk\s*:\s*$" )
      return;

    banner_type = "X-Powered-By-Plesk Server banner";

    if( "PleskWin" >< banner ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    if( "PleskLin" >< banner ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
    os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_x_powered_by_plesk_banner", port:port );
  }

  return;
}

function check_user_agent_banner( port, banner ) {

  local_var port, banner, banner_type;

  if( banner && banner = egrep( pattern:"^User-Agent\s*:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    if( banner =~ "^User-Agent\s*:\s*$" ) return;

    # nb: If our user agent is echoed back to us just ignore it...
    if( http_get_user_agent() >< banner ) return;

    banner_type = "HTTP User Agent banner";

    # nb:
    # - Collabora / LibreOffice Online
    # - User-Agent / Server banner depends on the queried endpoint. We're just adding all of them
    #   just to be sure...
    # - More info on the WebSocket server:
    #   - https://github.com/LibreOffice/online/blob/master/wsd/README
    #   - https://github.com/CollaboraOnline/online/blob/master/wsd/README
    #   - This is the only service i have seen so far which is responding with a User-Agent: header
    # - loolwsd/coolwsd is only running on Linux/Unix
    #
    # User-Agent: LOOLWSD HTTP Agent 6.4.10
    # User-Agent: LOOLWSD WOPI Agent 4.2.15
    # User-Agent: COOLWSD HTTP Agent 21.11.0.3
    # User-Agent: COOLWSD HTTP Agent 23.05.1.3
    # User-Agent: LOOLWSD WOPI Agent
    #
    if( banner =~ "User-Agent\s*:\s*[CL]OOLWSD (WOPI|HTTP) Agent" ) {
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
    os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_user_agent_banner", port:port );
  }
  return;
}

function check_daap_banner( port, banner ) {

  local_var port, banner, banner_type;

  if( banner && banner = egrep( pattern:"^DAAP-Server\s*:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    if( banner =~ "^DAAP-Server\s*:\s*$" ) return;

    # DAAP-Server: Ampache
    # DAAP-Server: daap-sharp
    # Both are cross-platform
    if( banner =~ "^DAAP-Server\s*:\s*(Ampache|daap-sharp)$" ) return;

    banner_type = "DAAP-Server banner";

    # DAAP-Server: iTunes/11.1b37 (OS X)
    # DAAP-Server: iTunes/12.9.5.5 (OS X)
    if( banner =~ "\(OS X\)" ) {
      os_register_and_report( os:"Mac OS X / macOS", cpe:"cpe:/o:apple:mac_os_x", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # DAAP-Server: iTunes/12.1.3.6 (Windows)
    if( banner =~ "\(Windows\)" ) {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Currently unknown OS:
    # DAAP-Server: AlbumPlayer 1.6.5.1

    os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"daap_server_banner", port:port );
  }

  return;
}

# nb: ignore_broken:TRUE is used here because no404.nasl might have set the remote host as "broken"
# due to the existence of a specific banner like "DAAP-Server" so that no web app scanning is done.
# But in this specific VT we still want to work with a possible existing banner so we're ignoring
# this information.
port   = http_get_port( default:80, ignore_broken:TRUE );
banner = http_get_remote_headers( port:port, ignore_broken:TRUE );
if( ! banner || banner !~ "^HTTP/1\.[01] " )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );

# nb: The order matters here, e.g. we might have a "Server: Apache (Debian)" banner but a more detailed Debian Release in the PHP banner
check_php_banner( port:port, host:host );
check_http_banner( port:port, banner:banner );
check_default_page( port:port );
check_x_powered_by_banner( port:port, banner:banner );
check_user_agent_banner( port:port, banner:banner );
check_daap_banner( port:port, banner:banner );
check_x_powered_by_plesk_banner( port:port, banner:banner );

# Outlook Web App (OWA) of Exchange < 15.x
# nb: This was placed down here because none of the functions above are matching.
if( concl = egrep( string:banner, pattern:"^X-OWA-Version\s*:.+", icase:TRUE ) ) {
  concl = chomp( concl );
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:"X-OWA-Version banner", port:port, banner:concl, desc:SCRIPT_DESC, runs_key:"windows" );
}

exit( 0 );
