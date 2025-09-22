# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105878");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:42 +0200 (Mon, 22 Aug 2016)");
  script_name('SSL/TLS: `preload` Missing in HSTS Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_hsts_http_detect.nasl");
  script_mandatory_keys("hsts/preload/missing/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#http-strict-transport-security-hsts");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6797");
  script_xref(name:"URL", value:"https://hstspreload.appspot.com/");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote web server is missing the 'preload' attribute in the
  HTTP Strict Transport Security (HSTS) header.");

  script_tag(name:"solution", value:"Submit the domain to the 'HSTS preload list' and add the
  'preload' attribute to the HSTS header.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hsts/preload/missing/port" ) )
  exit( 0 );

banner = get_kb_item( "hsts/" + port + "/banner");

log_message( port:port, data:'The remote web server is missing the "preload" attribute in the HSTS header.\n\nHSTS Header:\n\n' + banner );
exit( 0 );
