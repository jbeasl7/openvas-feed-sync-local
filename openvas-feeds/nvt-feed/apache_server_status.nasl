# SPDX-FileCopyrightText: 2005 StrongHoldNet
# SPDX-FileCopyrightText: New NASL / detection code since 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10677");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2020-25073");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-11 16:20:00 +0000 (Fri, 11 Sep 2020)");
  script_name("Apache HTTP Server /server-status Accessible (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 StrongHoldNet / 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://httpd.apache.org/docs/current/mod/mod_status.html");

  script_tag(name:"summary", value:"Requesting the URI /server-status provides information on the
  server activity and performance.");

  script_tag(name:"insight", value:"server-status is a Apache HTTP Server handler provided by the
  'mod_status' module and used to retrieve the server's activity and performance.");

  script_tag(name:"impact", value:"Requesting the URI /server-status gives throughout information
  about the currently running Apache to an attacker.");

  script_tag(name:"affected", value:"- All Apache installations with an enabled 'mod_status' module

  - FreedomBox through 20.13");

  script_tag(name:"vuldetect", value:"Checks if the /server-status page of Apache is accessible.");

  script_tag(name:"solution", value:"- If this feature is unused commenting out the appropriate
  section in the web servers configuration is recommended

  - If this feature is used restricting access to trusted clients is recommended

  - If the FreedomBox software is running on the target update the software to a later version");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/server-status";

buf = http_get_cache( item:url, port:port );

# e.g.
# <h1>Apache Server Status for example.com (via $IP)</h1>
# <title>Apache Status</title>
if( buf && buf =~ "^HTTP/1\.[01] 200" &&
    ( ">Apache Server Status" >< buf || "title>Apache Status</title>" >< buf ) ) {

  set_kb_item( name:"apache/server-status/detected", value:TRUE );
  set_kb_item( name:"apache/server-status/" + port + "/detected", value:TRUE );
  set_kb_item( name:"mod_jk_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_perl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_python_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_ssl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"openssl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"perl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"python_or_apache_status_info_error_pages/banner", value:TRUE );

  # <dl><dt>Server Version: Apache/2.4.25 (Debian) PHP/5.6.40-0+deb8u4 mod_python/3.3.1 Python/2.7.13 OpenSSL/1.0.2u mod_perl/2.0.10 Perl/v5.24.1</dt>
  sv = eregmatch( pattern:"Server Version: (Apache/[^<]+)", string:buf );
  if( sv[1] ) {
    # nb: Saving it into this format for all VTs checking something like "Server\s*:\s*Apache".
    set_kb_item( name:"www/server-status/banner/" + port, value:"Server: " + chomp( sv[1] ) );

    # nb: Used for the "Concluded" reporting in the VTs evaluating the string above to avoid
    # confusion on the "Server: " banner.
    set_kb_item( name:"www/server-status/banner/concluded/" + port, value:chomp( sv[0] ) );
  }

  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
