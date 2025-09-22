# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113634");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-01-27 10:34:33 +0100 (Mon, 27 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Plugins Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"HTTP based detection of WordPress plugins.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/");

  script_timeout(900);

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("wordpress_plugins.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach readme_file( keys( wordpress_plugins_info ) ) {

  if( ! infos = wordpress_plugins_info[readme_file] )
    continue;

  infos = split( infos, sep: "#---#", keep: FALSE );
  if( ! infos || max_index( infos ) < 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3] + ":";
  changelog_regex = infos[4];

  if( ! changelog_regex )
    changelog_regex = "= ([0-9.]+) =";

  url = dir + "/wp-content/plugins/" + readme_file;
  res = http_get_cache( port: port, item: url );

  if( ( concl = egrep( pattern: detect_regex, string: res, icase: TRUE ) ) &&
      # nb:
      # - The "Changelog" string contains either no or one space (previously "( ){0,1}" was used for
      #   that part)
      # - At least "SitePress Multilingual CMS" had only included that header and the "Stable tag:"
      #   string so that string was added at some point in time below
      # - Sometimes the "Stable tag:" includes a string so no version/number regex was used
      ( res =~ "Change ?log" || res =~ "Tested up to: ([0-9.]+)" || res =~ "\* (Add|Fix)(ed)?: " || res =~ "Stable tag: " ) ) {

    version = "unknown";
    # nb: Minor formatting change for the reporting.
    concl = chomp( concl );
    concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
    concluded = "  " + concl;

    if( "Stable tag" >!< vers_regex && cl = eregmatch( pattern: vers_regex, string: res, icase: TRUE ) )
      vers = eregmatch( pattern: changelog_regex, string: cl[1], icase: TRUE );
    else
      vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );

    if( vers[1] ) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    # nb: The Tatsu plugin is using "changelog.md" while the "WebP Converter for Media" changelog.txt
    kb_entry_name = ereg_replace( pattern: "/(readme|changelog)\.(md|txt)", string: readme_file, replace: "", icase: TRUE );
    insloc = ereg_replace( pattern: "/(readme|changelog)\.(md|txt)", string: url, replace: "", icase: TRUE );

    #nb: The Premium Starter Templates plugin changes slug through years
    if( kb_entry_name == "astra-premium-sites")
      kb_entry_name = "astra-pro-sites";

    # nb: Usually only the one without the "/http/" should be used for version checks.
    set_kb_item( name: "wordpress/plugin/" + kb_entry_name + "/detected", value: TRUE );
    set_kb_item( name: "wordpress/plugin/http/" + kb_entry_name + "/detected", value: TRUE );

    # nb: Some generic KB keys if we ever need to run this if multiple plugins have been detected.
    set_kb_item( name: "wordpress/plugin/detected", value: TRUE );
    set_kb_item( name: "wordpress/plugin/http/detected", value: TRUE );

    extra = "Plugin Page: https://wordpress.org/plugins/" + kb_entry_name + "/";

    register_and_report_cpe( app: "WordPress Plugin '" + name + "'",
                             ver: version,
                             concluded: concluded,
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: insloc,
                             regPort: port,
                             regService: "www",
                             conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ),
                             extra: extra );
  }
}

exit( 0 );
