# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108250");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-10-10 13:07:41 +0200 (Tue, 10 Oct 2017)");
  script_name('SSL/TLS: Check for `max-age` Attribute in HPKP Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_hpkp_http_detect.nasl");
  script_mandatory_keys("hpkp/available/port");

  script_add_preference(name:"Minimum max-age value (in seconds)", type:"entry", value:"5184000", id:1);

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote web server is using a too low value within the
  'max-age' attribute in the HTTP Public Key Pinning (HPKP) header.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"solution", value:"The recommended value should aim towards 60 days (5184000
  seconds) but heavily depends on your deployment scenario.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

max_age_check = int( script_get_preference( "Minimum max-age value (in seconds)", id:1 ) );
if( max_age_check <= 0 )
  max_age_check = 5184000;

if( ! port = get_kb_item( "hpkp/available/port" ) )
  exit( 0 );

if( isnull( current_max_age = get_kb_item( "hpkp/max_age/" + port ) ) )
  exit( 0 );

# The return of the above get_kb_item is "data"
current_max_age = int( current_max_age );
if( current_max_age <= 0 )
  exit( 0 ); # Something went wrong...

if( current_max_age < max_age_check ) {
  banner = get_kb_item( "hpkp/" + port + "/banner" );
  report = 'The remote web server is using a value of "' + current_max_age + '" within the "max-age" attribute in the HPKP header. ';
  report += 'This value is below the configured / minimal recommended value of "' + max_age_check + '".\n\nHPKP Header:\n\n' + banner;
  log_message( port:port, data:report );
}

exit( 0 );
