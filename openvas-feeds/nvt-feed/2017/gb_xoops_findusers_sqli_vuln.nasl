# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108137");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-13 12:06:51 +0200 (Thu, 13 Apr 2017)");
  script_cve_id("CVE-2017-7290");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-03 13:42:00 +0000 (Mon, 03 Apr 2017)");
  script_name("XOOPS 'findusers.php' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97230");
  script_xref(name:"URL", value:"https://gist.github.com/jk1986/3b304ac6b4ae52ae667bba380c2dce19");

  script_tag(name:"summary", value:"XOOPS is prone to an SQL injection vulnerability.");
  script_tag(name:"insight", value:"The flaw exists due to XOOPS allowing remote authenticated administrators to execute
  arbitrary SQL commands via the url parameter to findusers.php. An example attack uses 'into outfile'
  to create a backdoor program.");
  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"XOOPS version prior to 2.5.8.1");
  script_tag(name:"solution", value:"Upgrade to XOOPS version 2.5.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.5.8.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.8.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
