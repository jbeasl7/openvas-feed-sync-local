# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103786");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-12-05T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-05 05:05:31 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"creation_date", value:"2013-09-12 10:58:59 +0200 (Thu, 12 Sep 2013)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology NAS / DiskStation Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Synology NAS devices, DiskStation
  Manager (DSM) OS and application.");

  script_add_preference(name:"Synology NAS / DiskStation Manager Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Synology NAS / DiskStation Manager Web UI Password", value:"", type:"password", id:2);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("synology_func.inc");

port = http_get_port( default:5000 );

install = "/";

foreach url( make_list( "/", "/webman/index.cgi", "/index.cgi" ) ) {
  buf = http_get_cache( item:url, port:port );
  # nb: old detection rules do not work anymore for newer versions
  # nb: On 7.2 we have synoSDSjslib/dist/sds.bundle.js while previously it was synoSDSjslib/sds.js
  if( ( ( buf =~ "Synology(&nbsp;| )DiskStation") || ( buf =~ "synology\.com" && ( 'content="DiskStation' >< buf || "synoSDSjslib/" >< buf ) ) ) &&
    ( buf =~ "SYNO\.(SDS.Session|Core.Desktop)" || buf =~ '<meta name="description" content="(VirtualDSM|Synology NAS|DiskStation) provides a full-featured' ) ) {
    concl = "";
    version = "unknown";
    concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"synology/dsm/detected",value:TRUE );
    set_kb_item( name:"synology/dsm/http/detected", value:TRUE );
    set_kb_item( name:"synology/dsm/http/port", value:port );

    user = script_get_preference( "Synology NAS / DiskStation Manager Web UI Username", id:1 );
    pass = script_get_preference( "Synology NAS / DiskStation Manager Web UI Password", id:2 );

    if( ! user && ! pass ) {
      extra = "Note: No username and password for web authentication were provided. Please provide these for full version extraction.";
    } else if( ! user && pass ) {
      extra = "Note: Password for web authentication was provided but Username is missing.";
    } else if( user && ! pass ) {
      extra = "Note: Username for web authentication was provided but Password is missing.";
    } else if( user && pass ) {
      url = "/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login&account=" + user +
            "&passwd=" + pass + "&enable_syno_token=yes";

      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req );

      token = eregmatch( pattern:"X-SYNO-TOKEN\s*:\s*([0-9a-zA-Z]+)", string:res );
      id = http_get_cookie_from_header( buf:res, pattern:"id=([^;]+)" );
      did = http_get_cookie_from_header( buf:res, pattern:"did=([^;]+)" );

      if( ! isnull(token[1] ) && id && did ) {
        url = "/webapi/entry.cgi?api=SYNO.Core.Desktop.Initdata&version=1&method=get_user_service&SynoToken=" +
              token[1];

        cookie = "id=" + id + "; did=" + did;

        headers = make_array( "X-SYNO-TOKEN", token[1],
                              "X-Requested-With", "XMLHttpRequest",
                              "Cookie", cookie );

        req = http_get_req( port:port, url:url, add_headers:headers );
        res = http_keepalive_send_recv( port:port, data:req );

        # ","productversion":"7.1.1"
        vers = eregmatch( pattern:'"productversion"\\s*:\\s*"([0-9.]+)"', string:res );
        if( !isnull( vers[1] ) ) {
          concUrl += '\n    ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          version = vers[1];
          concl += '\n    ' + vers[0];

          # "buildnumber":"42962"
          build = eregmatch( pattern:'"buildnumber"\\s*:\\s*"([0-9]+)"', string:res );
          if( ! isnull( build[1] ) ) {
            version += "-" + build[1];
            concl += '\n    ' + build[0];

            # "smallfixnumber":"6"
            fix = eregmatch( pattern:'"smallfixnumber"\\s*:\\s*"([0-9]+)"', string:res );
            if( ! isnull( fix[1] ) && fix[1] != "0" ) {
              version += "-" + fix[1];
              concl += '\n    ' + fix[0];
            }
          }
        }

        url = "/webapi/entry.cgi?api=SYNO.Core.Desktop.Defs&version=1&method=getjs&SynoToken=" +
              token[1];

        req = http_get_req( port:port, url:url, add_headers:headers );
        res = http_keepalive_send_recv( port:port, data:req );

        # "upnpmodelname":"DS3622xs+"
        mod = eregmatch( pattern:'"upnpmodelname"\\s*:\\s*"([^"]+)"', string:res );
        if( ! isnull( mod[1] ) ) {
          set_kb_item( name:"synology/dsm/http/" + port + "/model", value:mod[1] );
          concl += '\n    ' + mod[0];
          concUrl += '\n    ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      } else {
        extra = "Note: Username and Password were provided but authentication failed.";
      }
    }

    if( version == "unknown" ) {
      # nb: this only works for newer versions, from 6.x onward
      url1 = "/synohdpack/synohdpack.version";
      #majorversion="7"
      #minorversion="1"
      #major="7"
      #minor="1"
      #micro="1"
      #productversion="7.1.1"
      #buildphase="GM"
      #buildnumber="42962"
      #smallfixnumber="0"
      #nano="0"
      #base="42962"
      res = http_get_cache( item:url1, port:port );
      if( res && res =~ "^HTTP/(1\.[01]|2) 200" ) {

        ver = eregmatch( pattern:'productversion="([0-9.]+)"', string:res );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          concUrl += '\n    ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
          concl += '\n    ' + ver[0];
        } else {
          # nb: This was first reported for 7.2.2; it seems productversion is missing
          #majorversion="7"
          #minorversion="2"
          #major="7"
          #minor="2"
          #micro="2"
          #buildphase="GM"
          #buildnumber="72806"
          #smallfixnumber="0"
          #nano="0"
          #base="72806"
          ver = eregmatch( pattern:'major="([0-9]+)"', string:res );
          if( ! isnull( ver[1] ) ) {
            version = ver[1];
            concUrl += '\n    ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
            concl += '\n    ' + ver[0];

            ver1 = eregmatch( pattern:'minor="([0-9]+)"', string:res );
            if( ! isnull( ver1[1] ) ) {
              version += "." + ver1[1];
              concl += '\n    ' + ver1[0];
            }
            ver2 = eregmatch( pattern:'micro="([0-9]+)"', string:res );
            if( ! isnull( ver2[1] ) && ( int( ver2[1] ) > 0 ) ) {
              version += "." + ver2[1];
              concl += '\n    ' + ver2[0];
            }
          } else {
            # nb: Version 5.0 has this file, but there is no "productversion" entry, so we use the majorversion.minorversion
            # since on those versions there were no micro versions used, as far as Release Notes can tell, it should be ok
            ver = eregmatch( pattern:'majorversion="([0-9]+)"', string:res );
            if( ! isnull( ver[1] ) ) {
              version = ver[1];
              concUrl += '\n    ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
              concl += '\n    ' + ver[0];

              ver1 = eregmatch( pattern:'minorversion="([0-9]+)"', string:res );
              if( ! isnull( ver1[1] ) ) {
                version += "." + ver1[1];
                concl += '\n    ' + ver1[0];
              }
            }
          }
        }
        # nb: we can add now build number and small fix number
        if( "unknown" >!< version ) {
          ver1 = eregmatch( pattern:'buildnumber="([0-9]+)"', string:res );
          if( ! isnull( ver1[1] ) ) {
            version += "-" + ver1[1];
            concl += '\n    ' + ver1[0];
          }

          ver2 = eregmatch( pattern:'smallfixnumber="([0-9]+)"', string:res );
          if( ! isnull( ver2[1] ) && int( ver2[1] ) > 0 ) {
            version += "-" + ver2[1];
            concl += '\n    ' + ver2[0];
          }
        }
      } else {
        # nb: For older versions ( < 4.3 ) the above solution does not work, but we can extract buildNumber
        # and based on the release history, we can reconstruct full version
        # see https://www.synology.com/en-us/releaseNote/DSM

        # nb: Starting with 4.3 versions, the syndefs.cgi method is no longer reliable, as the number after is no longer the build number
        # Instead, a "fullversion" entry got added in the SYNO.SDS.Session JSON, containing the build number.
        # eg. "fullversion" : "3810-s0"
        ver = eregmatch( pattern:'"fullversion"\\s*:\\s*"([0-9]+)([0-9a-z-]+)?"', string:buf );
        if( ! isnull( ver[1] ) ) {
          ver_str = synology_dsm_build_number_to_full_version( buildNumber:ver[1] );
          if( ! isnull( ver_str ) ) {
            version = ver_str;
            concl += '\n    ' + ver[0];
          }
        } else {
          # nb: Versions 4.2 and lower contain the build number in the syndefs.cgi?v=<nr>. They also might contain a "version" entry in the
          # SYNO.SDS.Session JSON, but that did not happen for version 3.0 - 3.2. Could not find targets 2.x and below.
          ver = eregmatch( pattern:'<script type="text/javascript" src="synodefs\\.cgi\\?v=([0-9]+)', string:buf );
          if( ! isnull( ver[1] ) ) {
            ver_str = synology_dsm_build_number_to_full_version( buildNumber:ver[1] );
            if( ! isnull( ver_str ) )
              version = ver_str;

            concl += '\n    ' + ver[0];
          }
        }
      }
      # nb: Try to extract model from here. Works only for versions < 6.0
      url = "/webman/synodefs.cgi";
      res = http_get_cache( item:url, port:port );
      if( res && res =~ "^HTTP/(1\.[01]|2) 200" ) {

        # eg: "upnpmodelname":"DS3615xs"
        mod = eregmatch( pattern:'"upnpmodelname":"([a-zA-Z0-9+]+)"', string:res );
        if( ! isnull( mod[1] ) ) {
          set_kb_item( name:"synology/dsm/http/" + port + "/model", value:mod[1] );
          concl += '\n    ' + mod[0];
          concUrl += '\n    ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    set_kb_item( name:"synology/dsm/http/" + port + "/version", value:version );

    if( concl )
      set_kb_item( name:"synology/dsm/http/" + port + "/concluded", value:chomp( concl ) );

    if( concUrl )
      set_kb_item( name:"synology/dsm/http/" + port + "/concludedUrl", value:concUrl );

    if( extra )
      set_kb_item( name:"synology/dsm/http/" + port + "/error", value:extra );

    exit( 0 );
  }
}
exit( 0 );
