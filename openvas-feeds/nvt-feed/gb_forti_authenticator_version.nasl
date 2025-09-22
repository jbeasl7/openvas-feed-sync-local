# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105221");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-02-18 10:02:43 +0100 (Wed, 18 Feb 2015)");
  script_name("Fortinet FortiAuthenticator Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("FortiOS/Authenticator/system");

  script_xref(name:"URL", value:"https://www.fortinet.com/products/identity-access-management/fortiauthenticator");

  script_tag(name:"summary", value:"SSH login-based detection of Fortinet FortiAuthenticator.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("FortiOS/Authenticator/system");
if( ! system )
  exit( 0 );

cpe = "cpe:/a:fortinet:fortiauthenticator";
vers = "unknown";

model = eregmatch( string:system, pattern:"Version\s*:\s*(FAC[^ ]*)" );

if( ! isnull( model[1] ) ) {
  mod = model[1];
  mod = chomp( mod );
  set_kb_item( name:"fortiauthenticator/model", value:mod );
}

version = eregmatch( pattern:"Version\s*:\s*FAC[^ ]* v([^-]+)", string:system );
if( ! isnull( version[1] ) ) {
  ver = version[1];
  for( i = 0; i < strlen( ver ); i++ ) {
    if( ver[i] == "." )
      continue;

    v += ver[ i ];

    if( i < ( strlen( ver ) - 1 ) )
      v += ".";
  }
  set_kb_item( name:"fortiauthenticator/version", value:v );
  cpe += ":" + v;
  vers = v;
}

b = eregmatch( pattern:"-build([^,]+),", string:system );
if( ! isnull( b[1] ) ) {
  build = b[1];
  build = ereg_replace( string:build, pattern:"^0", replace:"" );
  set_kb_item( name:"fortiauthenticator/build", value:build );
}

register_product( cpe:cpe, location:"ssh", port:0, service:"ssh-login" );

report = 'Detected Fortinet FortiAuthenticator (SSH)\n\n' +
         "Version: " + vers + '\n';

if( mod )
  report += "Model:   " + mod + '\n';

if( ! isnull( build ) )
  report += "Build:   " + build + '\n';

report += "CPE:     " + cpe;

log_message( port:0, data:report );

exit( 0 );
