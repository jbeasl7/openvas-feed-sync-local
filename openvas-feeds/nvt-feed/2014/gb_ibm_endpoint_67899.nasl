# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105129");
  script_cve_id("CVE-2014-0224");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("2023-07-26T05:05:09+0000");

  script_name("IBM Endpoint Manager 9.1 OpenSSL Man in the Middle Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21677842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67899");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow attackers to obtain
sensitive information by conducting a man-in-the-middle attack. This may lead to other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An OpenSSL advisory was announced on June 5, 2014 in several versions
of OpenSSL. Several vulnerabilities were detailed in this advisory. One affects IBM Endpoint Manager 9.1 --
the ChangeCipherSpec (CCS) Injection Vulnerability. This vulnerability can be exploited by a Man-in-the-middle
(MITM) attack allowing an attacker to eavesdrop and make falsifications between Root Server, Web Reports, Relay,
and Proxy Agent communications. An eavesdropping attacker can obtain console login credentials.");

  script_tag(name:"solution", value:"Upgrade all components to version 9.1.1117.");

  script_tag(name:"summary", value:"There is an OpenSSL vulnerability that could allow an attacker to decrypt
and modify traffic from a vulnerable client and server.");

  script_tag(name:"affected", value:"IBM Endpoint Manager 9.1 (9.1.1065, 9.1.1082, and 9.1.1088) are the only
affected versions. Previous versions are not affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");
  script_tag(name:"creation_date", value:"2014-12-03 13:45:19 +0100 (Wed, 03 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_require_ports("Services/www", 52311);
  script_mandatory_keys("ibm_endpoint_manager/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version !~ "^9\.1\.[0-9]+" ) exit( 0 );

fixed_version = '9.1.1117';

cv = split( version, sep:'.', keep:FALSE );

ck_version = cv[2];

if( int( ck_version ) < int( 1117 ) )
{
  report = 'Installed version: ' + version + '\nFixed version:     ' + fixed_version + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );