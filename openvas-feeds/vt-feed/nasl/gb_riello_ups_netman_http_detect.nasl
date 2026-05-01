# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140002");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-09-28 16:19:24 +0200 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Riello UPS / NetMan Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Riello NetMan network cards and the
  underlying uninterruptible power supply (UPS) device.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

detection_patterns = make_list(
  # "old" GUI:
  # <title>Netman 204 login</title>
  # <title>Netman 208</title>
  # nb: This had both "cgi-bin/login.cgi" and "cgi-bin/view.cgi"
  #
  # "new" GUI:
  # <title>NetMan 204</title>
  # nb: This had only "cgi-bin/login.cgi" but not "cgi-bin/view.cgi"
  #
  "^\s*<title>Net[Mm]an 20[48]( login)?</title>",

  # "old" GUI:
  # <form id="login" action="cgi-bin/login.cgi" method="post" onsubmit="this.submit.disabled='disabled'; this.submit.value='Please wait...'">
  # <form id="view" action="cgi-bin/view.cgi">
  #
  # "new" GUI:
  # <form action="cgi-bin/login.cgi" method="get" class="js-login-form">
  '"cgi-bin/(view|login)\\.cgi"',

  # "new" GUI:
  # And in a few cases the <title> tag got created via JavaScript and wasn't included in the HTML
  # source code so adding a few additional pattern to catch these.
  #
  # <h4 class="modal-title">Your Netman 204 is probably not connected, off or on a different IP address.</h4>
  # <p class="modal-body">Control if your Netman 204 is correctly plugged in, turned on and the network is correctly configured.</p>
  # <h4 class="modal-title">Are you sure to reboot Netman 204?</h4>
  #
  ">Your Netman( 20[48])? is probably not connected, off or on a different IP address\.<",
  ">Control if your Netman( 20[48])? is correctly plugged in, turned on and the network is correctly configured\.<",
  ">Are you sure to reboot Netman( 20[48])?\?<" );

url = "/";
res = http_get_cache( port:port, item:url );

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern( detection_patterns ) {

  concl = egrep( string:res, pattern:pattern, icase:FALSE );
  if( concl ) {

    # nb: Minor formatting change for the reporting.
    concl = split( concl, keep:FALSE );
    foreach _concl( concl ) {
      _concl = ereg_replace( string:_concl, pattern:"^(\s+)", replace:"" );
      concluded += '\n    ' + _concl;
    }

    found++;
  }
}

if( found > 1 ) {

  set_kb_item( name:"riello/netman/detected", value:TRUE );
  set_kb_item( name:"riello/netman/http/detected", value:TRUE );
  set_kb_item( name:"riello/netman/http/port", value:port );

  netman_card = "unknown";
  ups_fw_version  = "unknown";
  netman_app_version = "unknown";
  netman_sys_version = "unknown";
  ups_model = "unknown";
  conclUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( "Netman 204" >< res )
    netman_card = "204";
  else if ( "Netman 208" >< res )
    netman_card = "208";

  # nb: If anonymous "view" is possible we can extract the info from these...
  urls = make_list(
    "/cgi-bin/view_about.cgi", # nb: For older devices
    "/json/netman_data.json", # nb: On newer devices the info is spread across to endpoints...
    "/json/nominal_data.json"
  );

  foreach url( urls ) {

    res = http_get_cache( port:port, item:url );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    add_conc_url = FALSE;

    # nb: Some of the example below includes spaces and/or newlines as shown in the examples...

    if( ups_model == "unknown" ) {
      # "Old" cgi endpoint:
      # <tr><td><b>Model</b></td><td>UOD2            </td></tr>
      #
      # "New" json based endpoints:
      # "model": "UOD3            ",
      mod = eregmatch( string:res, pattern:'(>Model</b>\\s*</td>\\s*<td>\\s*|"model"\\s*:\\s*")([^ <&"]+)', icase:FALSE );
      if( mod[2] ) {
        ups_model = mod[2];
        # nb: As a few of the examples shows possible newlines they are getting strippe here...
        concluded += '\n    ' + str_replace( find:'\n', string:mod[0], replace:"" );
        add_conc_url = TRUE;
      }
    }

    if( ups_fw_version == "unknown" ) {
      # "Old" cgi endpoint:
      # <tr><td><b>Firmware version</b></td><td>SWM073-01-00</td></tr>
      #
      # "New" json based endpoints:
      # "firmware_version": "SWM073-01-00",
      fw_vers = eregmatch( string:res, pattern:'(>Firmware version</b>\\s*</td>\\s*<td>\\s*|"firmware_version"\\s*:\\s*")([^ <&"]+)', icase:FALSE );
      if( fw_vers[2] ) {
        ups_fw_version = fw_vers[2];
        # nb: As a few of the examples shows possible newlines they are getting strippe here...
        concluded += '\n    ' + str_replace( find:'\n', string:fw_vers[0], replace:"" );
        add_conc_url = TRUE;
      }
    }

    if( netman_app_version == "unknown" ) {
      # "Old" cgi endpoint:
      # </td><tr><td><b>Application version</b></td><td>
      # 01.04&nbsp;<img
      #
      # "New" json based endpoints:
      # "application_version": "02.12"
      app_vers = eregmatch( string:res, pattern:'(>Application version</b>\\s*</td>\\s*<td>\\s*|"application_version"\\s*:\\s*")([^ <&"]+)', icase:FALSE );
      if( app_vers[2] ) {
        netman_app_version = app_vers[2];
        # nb: As a few of the examples shows possible newlines they are getting strippe here...
        concluded += '\n    ' + str_replace( find:'\n', string:app_vers[0], replace:"" );
        add_conc_url = TRUE;
      }
    }

    if( netman_sys_version == "unknown" ) {
      # "Old" cgi endpoint:
      # </td><tr><td><b>System version</b></td><td>
      # S15-2</td><tr>
      #
      # "New" json based endpoints:
      # "system_version": "S17-2"
      sys_vers = eregmatch( string:res, pattern:'(>System version</b>\\s*</td>\\s*<td>\\s*|"system_version"\\s*:\\s*")([^ <&"]+)', icase:FALSE );
      if( sys_vers[2] ) {
        netman_sys_version = sys_vers[2];
        # nb: As a few of the examples shows possible newlines they are getting strippe here...
        concluded += '\n    ' + str_replace( find:'\n', string:sys_vers[0], replace:"" );
        add_conc_url = TRUE;
      }
    }

    if( netman_card == "unknown" ) {
      # "Name": "Netman 208",
      card = eregmatch( pattern:'"Name"\\s*:\\s*"Netman ([0-9]+)"', string:res );
      if( ! isnull( card[1] ) )
        netman_card = card[1];
    }

    if( add_conc_url )
      conclUrl += '\n    ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # nb: No need to continue if all info is there...
    if( ups_model != "unknown" && ups_fw_version != "unknown" &&
        netman_app_version != "unknown" && netman_sys_version != "unknown" && netman_card != "unknown" )
      break;
  }

  set_kb_item( name:"riello/netman/http/" + port + "/ups_model", value:ups_model );
  set_kb_item( name:"riello/netman/http/" + port + "/ups_fw_version", value:ups_fw_version );
  set_kb_item( name:"riello/netman/http/" + port + "/netman_card", value:netman_card );
  set_kb_item( name:"riello/netman/http/" + port + "/netman_app_version", value:netman_app_version );
  set_kb_item( name:"riello/netman/http/" + port + "/netman_sys_version", value:netman_sys_version );
  set_kb_item( name:"riello/netman/http/" + port + "/concludedUrl", value:conclUrl );
  set_kb_item( name:"riello/netman/http/" + port + "/concluded", value:concluded );
}

exit( 0 );
