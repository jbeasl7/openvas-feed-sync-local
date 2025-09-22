# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900710");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Internet Information Services (IIS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add a IIS/banner script_mandatory_keys because the VT is also doing a detection based
  # on standard/404 pages or redirects.

  script_tag(name:"summary", value:"HTTP based detection of Microsoft Internet Information Services
  (IIS) and the underlying Microsoft Windows operating system version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

detected = FALSE;
version = "unknown";

if( concl = egrep( string:banner, pattern:"^Server\s*:\s*(Microsoft-)?IIS", icase:TRUE ) ) {
  concluded = chomp( concl );
  detected = TRUE;
  vers = eregmatch( pattern:"Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)", string:concl, icase:TRUE );
  if( ! isnull( vers[2] ) )
    version = vers[2];
}

# For Proxy setups where e.g. an nginx is in front of the IIS.
if( ! detected || version == "unknown" ) {

  check_urls = make_list( "/vt-test-non-existent.html",
                          "/vt-test/vt-test-non-existent.html",
                          "/vt-test-non-existent.aspx",
                          "/vt-test/vt-test-non-existent.aspx"
                        );

  # We might also be able to catch the IIS banner if we're calling an existing .aspx file so we're
  # adding the first found .asp/.aspx file to the list in addition to the two above.
  asp_list = http_get_kb_file_extensions( port:port, host:host, ext:"asp*" );
  if( asp_list[0] )
    check_urls = make_list( check_urls, asp_list[0] );

  # Some found systems had also responded with a redirect, following the redirect might
  # also help to grab the banner.
  if( banner =~ "^HTTP/1\.[01] 30[0-9]" ) {
    loc = http_extract_location_from_redirect( port:port, data:banner, current_dir:"/" );
    if( loc )
      check_urls = make_list( check_urls, loc );
  }

  foreach check_url( check_urls ) {
    banner = http_get_remote_headers( port:port, file:check_url );
    if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
      continue;

    if( concl = egrep( string:banner, pattern:"^Server\s*:\s*(Microsoft-)?IIS", icase:TRUE ) ) {
      detected = TRUE;
      vers = eregmatch( pattern:"Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)", string:concl, icase:TRUE );
      if( ! isnull( vers[2] ) ) {
        if( concluded )
          concluded += '\n';
        concluded += chomp( concl );
        concl_url = http_report_vuln_url( port:port, url:check_url, url_only:TRUE );
        version = vers[2];
      }
      break;
    }
  }
}

if( detected ) {

  install = port + "/tcp";
  set_kb_item( name:"IIS/installed", value:TRUE );
  set_kb_item( name:"microsoft/iis/detected", value:TRUE );
  set_kb_item( name:"microsoft/iis/http/detected", value:TRUE );

  set_kb_item( name:"microsoft/spts_or_iis/detected", value:TRUE );
  set_kb_item( name:"microsoft/spts_or_iis/http/detected", value:TRUE );
  set_kb_item( name:"microsoft/spts_or_iis/http/" + host + "/" + port + "/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
  # supporting these.
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"yes" );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:internet_information_services:" );
  if( ! cpe )
    cpe = "cpe:/a:microsoft:internet_information_services";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Microsoft Internet Information Services (IIS)",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:concl_url,
                                            concluded:concluded ),
               port:port );

  # nb:
  # - Based on https://en.wikipedia.org/wiki/Internet_Information_Services#History
  # - Some IIS versions are shipped with two or more OS variants so registering all here
  # - IMPORTANT: Before registering two or more OS make sure that all OS variants have reached their
  #   EOL as we currently can't control / prioritize which of the registered OS is chosen for the
  #   "BestOS" and we would e.g. report a Server 2012 as EOL if Windows 8 was chosen
  # - The "keep" is used below to mark the ones with OS variants matching the important note above
  #   which shouldn't be registered yet

  banner_type = "Microsoft IIS HTTP Server banner";
  SCRIPT_DESC = "Microsoft Internet Information Services (IIS) Detection (HTTP)";

  if( version != "unknown" ) {

    if( version == "10.0" ) {
      # keep: os_register_and_report( os:"Microsoft Windows Server 2022", cpe:"cpe:/o:microsoft:windows_server_2022", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # keep: os_register_and_report( os:"Microsoft Windows Server 2019", cpe:"cpe:/o:microsoft:windows_server_2019", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # keep: os_register_and_report( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # keep: os_register_and_report( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows Server 2022, Microsoft Windows Server 2019, Microsoft Windows Server 2016 or Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "8.5" ) {
      os_register_and_report( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "8.0" ) {
      os_register_and_report( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "7.5" ) {
      os_register_and_report( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "7.0" ) {
      os_register_and_report( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "6.0" ) {
      os_register_and_report( os:"Microsoft Windows Server 2003 R2", cpe:"cpe:/o:microsoft:windows_server_2003:r2", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      os_register_and_report( os:"Microsoft Windows XP Professional x64", cpe:"cpe:/o:microsoft:windows_xp:-:-:x64", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "5.1" ) {
      os_register_and_report( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "5.0" ) {
      os_register_and_report( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "4.0" ) {
      os_register_and_report( os:"Microsoft Windows NT 4.0 Option Pack", cpe:"cpe:/o:microsoft:windows_nt:4.0", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "3.0" ) {
      os_register_and_report( os:"Microsoft Windows NT 4.0 SP2", cpe:"cpe:/o:microsoft:windows_nt:4.0:sp2", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "2.0" ) {
      os_register_and_report( os:"Microsoft Windows NT", version:"4.0", cpe:"cpe:/o:microsoft:windows_nt", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else if( version == "1.0" ) {
      os_register_and_report( os:"Microsoft Windows NT", version:"3.51", cpe:"cpe:/o:microsoft:windows_nt", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    }

    else {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # nb: We also want to report an unknown OS if none of the above patterns for Windows is matching
      os_register_unknown_banner( banner:concluded, banner_type_name:banner_type, banner_type_short:"iis_http_banner", port:port );
    }
  } else {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    # nb: Here we don't want to report an unknown OS as the version wasn't extracted...
  }
}

exit( 0 );
