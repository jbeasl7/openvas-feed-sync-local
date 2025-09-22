# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100773");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe ColdFusion Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Adobe ColdFusion.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

base = "/CFIDE";
file = "/administrator/index.cfm";

url1 = base + file;
res1 = http_get_cache( port:port, item:url1 );

# nb: A few older systems are using that one
url2 = "/enter.cfm";
res2 = http_get_cache( port:port, item:url2 );

# Some systems which only have one of these in the source code:
# <script type="text/javascript" src="/cf_scripts/scripts/cfform.js"></script>
# <link href="http://<redacted>:80/cf_scripts/scripts/assets/style.css"
# <img src="https://<redacted>:443/cf_scripts/scripts/assets/spot.png" />
# <script type="text/javascript" src="/cf_scripts/scripts/masks.js"></script>
#
# Those might exist on the index page (which could be also a 404) or an error page so a single
# pattern is used for the next two requests.
pattern = "^\s*<(script|link|img).+/cf_scripts/scripts/((cfform|masks)\.js|assets/(style\.css|spot\.png))";

url3 = "/";
res3 = http_get_cache( port:port, item:url3, fetch404:TRUE );
if( res3 =~ "^HTTP/1\.[01] 302" ) {
  url5 = http_extract_location_from_redirect( port:port, data:res3, current_dir:url3 );
  if( url5 )
    res5 = http_get_cache( port:port, item:url5, fetch404:TRUE );
}

# And the last one based on some fingerprinting on a possible error page just to be sure that
# we're detecting the product if everything else failed (e.g. for active checks)
url4 = "/vt-test-non-existent.cfm";
res4 = http_get_cache( port:port, item:url4, fetch404:TRUE );

if( "<title>ColdFusion Administrator Login</title>" >< res1 || "ColdFusion" >< res1 ) {
  found = TRUE;
  concUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
}

if( "<title>ColdFusion Administrator Login</title>" >< res2 ) {
  found = TRUE;
  if( concUrl )
    concUrl += '\n';
  concUrl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );
}

if( egrep( string:res3, pattern:pattern, icase:FALSE ) ) {
  found = TRUE;
  if( concUrl )
    concUrl += '\n';
  concUrl += http_report_vuln_url( port:port, url:url3, url_only:TRUE );
}

if( ">ColdFusion documentation<" >< res4 ||
    egrep( string:res4, pattern:pattern, icase:FALSE ) ) {
  found = TRUE;
  if( concUrl )
    concUrl += '\n';
  concUrl += http_report_vuln_url( port:port, url:url4, url_only:TRUE );
}

if( egrep( string:res5, pattern:pattern, icase:FALSE ) ) {
  found = TRUE;
  if( concUrl )
    concUrl += '\n';
  concUrl += http_report_vuln_url( port:port, url:url5, url_only:TRUE );
}

if( found ) {

  install = "/";

  url = base + "/adminapi/administrator.cfc?method=getBuildNumber";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:TRUE );

  # 2021,0,0,323925
  version = eregmatch( pattern:"([0-9]+,[0-9]+,[0-9]+,[0-9]+)", string:buf );
  if( ! isnull( version[1] ) ) {
    cf_version = str_replace( string:version[1], find:",", replace:"." );
    concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  if( ! cf_version ) {
    url = base + "/services/pdf.cfc?wsdl";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # 10.0.10.284825
      version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    url = base + "/adminapi/base.cfc?wsdl";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # (8|9).0.0.251028
      version = eregmatch( pattern:"WSDL created by ColdFusion version ([0-9,]+)-->", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    url = base + "/administrator/settings/version.cfm";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # (6|7).1.0.hf53797_61
      version = eregmatch( pattern:"Version: ([0-9,hf_]+)</strong>", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = str_replace( string:version[1], find:",", replace:"." );
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        # ColdFusion &#x28;2021 Release
        version = eregmatch( pattern:"ColdFusion[^;]+;([0-9]+) Release", string:buf );
        if( ! isnull( version[1] ) ) {
          cf_version = str_replace( string:version[1], find:",", replace:"." );
          concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }

  if( ! cf_version ) {

    # nb: This only includes the major version. Due to this some special handling in version based
    # VTs needs to be applied (see existing examples).
    url = base + "/administrator/help/index.html";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "ColdFusion" >< buf ) {
      # Configuring and Administering ColdFusion 11
      version = eregmatch( pattern:"Configuring and Administering ColdFusion ([0-9]+)", string:buf );
      if( ! isnull( version[1] ) ) {
        cf_version = version[1];
        concUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  if( ! cf_version ) {
    cf_version = "unknown";
    cpe = "cpe:/a:adobe:coldfusion";
  } else {
    cpe = "cpe:/a:adobe:coldfusion:" + cf_version;
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  set_kb_item( name:"adobe/coldfusion/detected", value:TRUE );
  set_kb_item( name:"adobe/coldfusion/http/detected", value:TRUE );

  log_message( data:build_detection_report( app:"Adobe ColdFusion", version:cf_version, install:install,
                                            cpe:cpe, concluded:version[0], concludedUrl:concUrl ),
               port:port );

  exit( 0 );
}

exit( 0 );
