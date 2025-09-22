# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105613");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-20 16:20:47 +0200 (Wed, 20 Apr 2016)");
  script_name("Cisco Prime Infrastructure (PIS) Web Interface Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Prime Infrastructure (PIS) web
  interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

source = "http";

port = http_get_port( default:443 );

url = "/webacs/pages/common/login.jsp";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "Prime Infrastructure" >< buf ) {

  rep_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  vers = "unknown";
  m_buf = buf;

  set_kb_item( name:"cisco/pis/http/port", value:port );
  set_kb_item( name:"cisco/pis/detected", value:TRUE );
  set_kb_item( name:"cisco/pis/http/detected", value:TRUE );

  cpe = "cpe:/a:cisco:prime_infrastructure";

  url = "/webacs/pages/common/updateQuickView.jsp";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "Critical Fixes" >< buf )
  {
    lines = split( buf );
    foreach line ( lines )
    {
      if( line =~ 'var arr.*"Critical Fixes"' )
      {
        if( '"id"' >< line )
          sep = '"id"';
        else
          sep = '"description"';

        ids = split( line, sep:sep, keep:TRUE );
        foreach id ( ids )
        {
          if( "TECH PACK" >< id ) continue;
          _p = eregmatch( pattern:'"name":"PI ([0-9]+\\.[^"]+)"', string:id );
          if( ! isnull( _p[1] ) )
          {
            installed_patches += _p[1] + '\n';
          }
        }
        break;
      }
    }
  }

  if( installed_patches )
  {
    set_kb_item( name:"cisco_pis/" + source + "/installed_patches", value:installed_patches );

    patches = split( installed_patches, keep:FALSE );
    foreach patch ( patches )
    {
      if( "Update" >< patch || patch =~ '[a-zA-Z ]+' )
      {
        p = eregmatch( pattern:'(^[0-9.]+)', string:patch );
        if( ! isnull( p[1] ) )
          patch = p[1];
      }

      if( ! max_patch_version )
        max_patch_version = patch;
      else
        if( version_is_less( version:max_patch_version, test_version:patch ) )
          max_patch_version = patch;
    }

    set_kb_item( name:"cisco_pis/" + source + "/max_patch_version", value:max_patch_version );
    vers = chomp( max_patch_version );
    set_kb_item( name:"cisco_pis/" + source + "/version", value:vers );
    cpe += ":" + max_patch_version;
    concluded_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  # First check location for newer versions (see comment in the next check below)
  if( vers == 'unknown' )
  {
    url = "/webacs/js/xmp/nls/xmp.js";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # file_version: "Version: 3.0",
    version = eregmatch( pattern:'file_version: "Version: ([0-9.]+)",', string:buf );
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      set_kb_item( name:"cisco_pis/" + source + "/version", value:vers );
      concluded_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  if( vers == 'unknown' )
  {
    # nb: Newer versions of PIS (e.g. 3.0.0) have commented out that one
    # like // dojo.query(".productVersion")[0].innerHTML= "Version: 2.2";
    version = eregmatch( pattern:'[^/]*dojo\\.query\\("\\.productVersion"\\)\\[0\\]\\.innerHTML= .Version: ([0-9.]+[^\'"]+).;', string:m_buf );
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      set_kb_item( name:"cisco_pis/" + source + "/version", value:vers );
    }
  }

  report = 'Cisco Prime Infrastructure Web Interface is running at this port.\n';
  if( vers ) report += 'Version: ' + vers + '\n';
  report += 'URL: ' + rep_url + '\nCPE: ' + cpe + '\n';
  if( max_patch_version ) report += 'Max patch version installed: PI ' + max_patch_version + '\n';
  if( installed_patches ) report += '\nInstalled Patches:\n' + installed_patches + '\n';
  if( concluded_url )     report += '\nVersion concluded from:\n' + concluded_url;

  log_message( port:port, data:report );
}

exit( 0 );
