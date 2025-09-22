# SPDX-FileCopyrightText: 2005 deepquest
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11833");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("EZsite Forum Discloses Passwords to Remote Users - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 deepquest");
  script_family("Web application abuses");
  script_dependencies("gb_microsoft_iis_http_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote host is running EZsite Forum.

  It is reported that this software stores usernames and passwords in
  plaintext form in the 'Database/EZsiteForum.mdb' file. A remote user
  can reportedly download this database.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

# nb: No get_app_location() as IIS is not "directly" affected and the initial version of
# this VT had only checked for the banner of IIS.
if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

foreach dir( make_list_unique( "/forum", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/Database/EZsiteForum.mdb";

  if( http_vuln_check( port:port, url:url, pattern:"Standard Jet DB" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
