# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwik:piwik";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900992");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4140");
  script_name("Piwik 0.2.35 - 0.4.3 PHP Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37314");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/12/14/1");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0910-exploits/piwik-upload.txt");

  script_category(ACT_DESTRUCTIVE_ATTACK); # nb: Might overwrite files
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_piwik_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwik/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute malicious PHP
  code to compromise the remote machine running the vulnerable application.");

  script_tag(name:"affected", value:"Open Flash Chart version 2 Beta 1 through 2.x

  Piwik version 0.2.35 through 0.4.3 on all platforms");

  script_tag(name:"insight", value:"This flaw is due to improper validation of data passed into 'name' and
  'HTTP_RAW_POST_DATA' parameters in ofc_upload_image.php which can be exploited
  to create php files containing malicious php code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Piwik is prone to PHP Code Execution vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" )
  dir = "";

vt_strings = get_vt_strings();
rand = vt_strings["lowercase_rand"];

url = dir + "/libs/open-flash-chart/php-ofc-library/ofc_upload_image.php?name=" + rand;

request = http_get(item:url, port:port);
response = http_keepalive_send_recv(port:port, data:request);

if(rand >< response && "tmp-upload-images" >< response &&
    egrep(pattern:"^HTTP/1\.[01] 200", string:response))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
