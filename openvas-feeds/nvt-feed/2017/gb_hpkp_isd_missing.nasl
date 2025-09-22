# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108249");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name('SSL/TLS: `includeSubDomains` Missing in HPKP Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_hpkp_http_detect.nasl");
  script_mandatory_keys("hpkp/includeSubDomains/missing/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote web server is missing the 'includeSubDomains'
  attribute in the HTTP Public Key Pinning (HPKP) header.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"solution", value:"Add the 'includeSubDomains' attribute to the HPKP header.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hpkp/includeSubDomains/missing/port" ) )
  exit( 0 );

banner = get_kb_item( "hpkp/" + port + "/banner" );

log_message( port:port, data:'The remote web server is missing the "includeSubDomains" attribute in the HPKP header.\n\nHPKP Header:\n\n' + banner );
exit( 0 );
