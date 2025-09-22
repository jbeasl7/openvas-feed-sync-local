# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:filemaker:filemaker_pro:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113591");
  script_version("2024-03-29T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-03-29 05:05:27 +0000 (Fri, 29 Mar 2024)");
  script_tag(name:"creation_date", value:"2019-11-28 11:40:00 +0200 (Thu, 28 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Claris FileMaker Pro Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't use "filemaker/banner" from gb_get_http_banner.nasl here due to the redirect check
  # below.

  script_tag(name:"summary", value:"HTTP based detection of Claris FileMaker Pro.");

  script_xref(name:"URL", value:"https://www.claris.com/filemaker/");
  script_xref(name:"URL", value:"https://www.claris.com/platform/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

banner = http_get_remote_headers( port: port );

# Server: FileMakerPro/4.0
# Server: FileMakerPro/6.0Jv3 WebCompanion/6.0Jv1
# Server: FileMakerPro/5.0
# Server: FileMakerPro/6.0Tv3 WebCompanion/6.0v1
if( ! concl = egrep( string: banner, pattern: "^[Ss]erver\s*:\s*FileMakerPro", icase: FALSE ) ) {

  # nb: Some (older?) systems are using a 302 redirect and only are exposing the banner on that
  if( banner =~ "^HTTP/1\.[01] 30[0-9]" ) {

    if( loc = http_extract_location_from_redirect( port: port, data: banner, current_dir: "/" ) ) {

      banner = http_get_remote_headers( port: port, file: loc );
      if( concl = egrep( string: banner, pattern: "^[Ss]erver\s*:\s*FileMakerPro", icase: FALSE ) ) {
        conclUrl = http_report_vuln_url( port: port, url: loc, url_only: TRUE );
        found = TRUE;
        concl = chomp( concl );
      }
    }
  }
} else {
  conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
  found = TRUE;
  concl = chomp( concl );
}

if( found ) {

  set_kb_item( name: "filemaker/pro/detected", value: TRUE );
  set_kb_item( name: "filemaker/pro/http/detected", value: TRUE );

  version = "unknown";

  vers = eregmatch( string: banner, pattern: "FileMakerPro/([0-9][0-9A-Za-z.]+)" );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  register_and_report_cpe( app: "Claris FileMaker Pro",
                           ver: version,
                           concluded: concl,
                           conclUrl: conclUrl,
                           base: CPE,
                           cpeLower: TRUE,
                           expr: "([0-9.]+)([A-Za-z0-9.]+)?",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );
