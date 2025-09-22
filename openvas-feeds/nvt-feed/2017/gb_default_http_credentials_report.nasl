# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103240");
  script_version("2025-05-23T15:42:02+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-1999-0501",
                "CVE-1999-0502",
                "CVE-1999-0507",
                "CVE-1999-0508",
                "CVE-2004-1791",  # Edimax AR-6004. BR6228nS/BR6228nC/BR6428n/BR6258n/BR-6574N devices are using these as well.
                "CVE-2023-32645", # Yifan YF325 routers
                "CVE-2024-9643",  # Four-Faith routers
                "CVE-2024-20439", # Cisco Smart Licensing Utility
                "CVE-2024-27170", # Toshiba printers. See https://pierrekim.github.io/blog/2024-06-27-toshiba-mfp-40-vulnerabilities.html#hardcoded-credentials-webdav
                "CVE-2024-28987", # SolarWinds Web Help Desk (WHD)
                "CVE-2024-46328"  # VONETS VAP11G-300
               );
  script_tag(name:"last_modification", value:"2025-05-23 15:42:02 +0000 (Fri, 23 May 2025)");
  script_tag(name:"creation_date", value:"2017-01-06 13:47:00 +0100 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 19:35:32 +0000 (Fri, 13 Sep 2024)");
  script_name("HTTP Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_dependencies("default_http_auth_credentials.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("default_http_auth_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs
  # to choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd
  # database.

  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"It was possible to login into the remote Web Application using
  default credentials.");

  script_tag(name:"vuldetect", value:"Reports default credentials detected by the VT
  'HTTP Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108041).");

  script_tag(name:"insight", value:"As the VT 'HTTP Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108041) might run into a timeout the actual reporting of this
  vulnerability takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

credentials = get_kb_list( "default_http_auth_credentials/" + host + "/" + port + "/credentials" );
if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials (<URL>:<User>:<Password>:<HTTP status code>)\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    url_user_pass = split( credential, sep:"#-----#", keep:FALSE );
    report += http_report_vuln_url( port:port, url:url_user_pass[0], url_only:TRUE ) + ":" + url_user_pass[1] + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  count = get_kb_item( "default_http_auth_credentials/" + host + "/" + port + "/too_many_logins" );
  if( count ) {
    report += '\nRemote host accept more than ' + count + ' logins. This could indicate some error or some "broken" web application.\nScanner stops testing for default logins at this point.';
    log_message( port:port, data:report );
    exit( 0 );
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
