# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140195");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-17 16:36:11 +0100 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("GitHub Enterprise WebGUI / Management Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the GitHub Enterprise WebGUI or
  Management Console.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8443 );

setup_detected = FALSE;

# nb:
# - "/setup/start" is redirecting to "/setup/unlock" if already configured / installed
# - "/setup/unlock" is redirecting to "/setup/start" if not already configured / installed
foreach dir( make_list( "/login", "/setup/unlock", "/setup/start" ) ) {

  buf = http_get_cache( item:dir, port:port );
  if( ! buf || ( buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 402" ) )
    continue; # nb: 402 for the case where the license expired.

  # nb:
  # - Only report the management console once...
  # - In recent versions this is not required as one is redirecting to the "other" endpoint
  #   but older versions might have behave differently...
  if( setup_detected )
    break;

  detected = FALSE;
  version  = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:dir, url_only:TRUE );

  # <title>GitHub Enterprise preflight check</title>
  # <title>Setup GitHub Enterprise</title>
  #
  if( buf =~ "<title>(Setup )?GitHub Enterprise( preflight check)?</title>" ||
      "Please enter your password to unlock the GitHub Enterprise management" >< buf ||
      "GitHub Enterprise requires one of the following" >< buf ||
      'enterprise.github.com/support">contact support' >< buf ) {

    app_name = "GitHub Enterprise Management Console";
    install  = "/setup";
    detected = TRUE;

    # nb: See note above...
    if( "<title>Setup GitHub Enterprise</title>" >< buf )
      setup_detected = TRUE;

    set_kb_item( name:"github/enterprise/management_console/detected", value:TRUE );
    set_kb_item( name:"github/enterprise/management_console/http/detected", value:TRUE );
  }

  # <title>GitHub Enterprise is in replication mode.</title>
  #
  #      <h1>Server in replication mode.</h1>
  #      <p>
  #        This GitHub Enterprise instance is configured as a replication node and cannot serve requests.
  #        The primary instance can be reached at <a href="http://redacted">redacted</a>
  #      </p>
  #
  # or:
  #
  # <title>Sign in to your account <UTF-8 dot> GitHub</title>
  #
  # <meta name="runtime-environment" content="enterprise">
  #
  # <img alt="GitHub Enterprise logo" src="https://<redacted>/assets/gh-enterprise-logo-4ef2d1e6467e.svg" width="204">
  #
  else if( ( buf =~ "<title>GitHub . Enterprise</title>" && # nb: The dot is expected here as the title contains an UTF-8 char which we can't use in VTs yet...
             '<meta name="description" content="GitHub is where people build software.' >< buf ) ||
           buf =~ '<img alt="GitHub Enterprise logo" src=".*/images/modules/enterprise/gh-enterprise-logo.svg"' ||
           "<title>GitHub Enterprise is in replication mode.</title>" >< buf ||
           "This GitHub Enterprise instance is configured as a replication node and cannot serve requests." >< buf ||
           ( buf =~ "<title>Sign in to your account[^<]+GitHub</title>" && buf =~ '(content="enterprise"|"GitHub Enterprise logo"|/gh-enterprise-logo)' ) ||
           ( "Sorry, your GitHub Enterprise license expired" >< buf && "<h1>License Expired</h1>" >< buf )
         ) {

    app_name = "GitHub Enterprise WebGUI";
    install  = "/";
    detected = TRUE;
    set_kb_item( name:"github/enterprise/webgui/detected", value:TRUE );
    set_kb_item( name:"github/enterprise/webgui/http/detected", value:TRUE );
  }

  if( detected ) {

    # <li><a href="https://help.github.com/enterprise/2.11">Help</a></li>
    # <li class="mr-3"><a href="https://help.github.com/enterprise/2.13" class="link-gray">Help</a></li>
    # <li class="mr-3"><a href="https://help.github.com/enterprise/2.14" class="link-gray">Help</a></li>
    # <a href="https://docs.github.com/enterprise-server@3.13" data-view-component="true" class="Link--secondary Link">Help</a>
    # <a href="https://docs.github.com/enterprise-server@3.13/admin/guides/installation/configuring-time-synchronization/">
    #
    # nb:
    # - Only the major release seems to be included here so this can't be used for version checks
    # - Still useful for EOL reporting in gsf/2023/github/gb_github_enterprise_eol.nasl
    # - In both previous cases we might be able to extract the version
    #
    vers = eregmatch( pattern:'<a href="https://(help\\.github\\.com/enterprise/|docs\\.github\\.com/enterprise-server@)([0-9.]+)[^"]*"', string:buf );
    if( vers[2] )
      version = vers[2];

    set_kb_item( name:"github/enterprise/detected", value:TRUE );
    set_kb_item( name:"github/enterprise/http/detected", value:TRUE );
    register_and_report_cpe( app:app_name, ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:github:github_enterprise:", expr:"^([0-9.]+)", regPort:port, regService:"www", insloc:install );
  }

  # nb: No exit(0); as we want to detect both "variants" of the (login) panels.
}

exit( 0 );
