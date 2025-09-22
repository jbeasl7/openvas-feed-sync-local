# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105337");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2015-08-28 16:12:01 +0200 (Fri, 28 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Intel Active Management Technology (AMT) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 16992);
  script_mandatory_keys("IAMT/banner");

  script_tag(name:"summary", value:"HTTP based detection of Intel Active Management Technology
  (AMT).");

  script_xref(name:"URL", value:"https://www.intel.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:16992 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

if( ! concl = egrep( string:banner, pattern:"^Server\s*:\s*Intel\(R\) Active Management Technology", icase:TRUE ) )
  exit( 0 );

vers = "unknown";
location = "/";

concl = chomp( concl );

set_kb_item( name:"intel/amt/detected", value:TRUE );
set_kb_item( name:"intel/amt/http/detected", value:TRUE );

vers = eregmatch( pattern:"[Ss]erver\s*:\s*Intel\(R\) Active Management Technology ([0-9.]+)", string:banner );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  concl = vers[0];
}

# nb: Despite NIST is using a `cpe:/o` CPE no OS reporting/registration is done for this as the
# underlying OSes like Windows might be not reported.
cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/o:intel:active_management_technology_firmware:" );
if( ! cpe )
  cpe = "cpe:/o:intel:active_management_technology_firmware";

register_product( cpe:cpe, location:location, port:port, service:"www" );

log_message( data:build_detection_report( app:"Intel Active Management Technology (AMT)", version:version,
                                          install:location, cpe:cpe, concluded:concl ),
             port:port );

exit( 0 );
