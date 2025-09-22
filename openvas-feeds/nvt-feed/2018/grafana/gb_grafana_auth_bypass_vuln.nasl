# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113260");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-31 12:33:34 +0200 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 17:26:00 +0000 (Tue, 05 Mar 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-15727");

  script_name("Grafana Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an Authentication Bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An attacker can generate a valid remember me cookie knowing only a username of an LDAP or OAuth user.");
  script_tag(name:"impact", value:"Knowing only the username, an attacker can get access with the privilege level of any user.");
  script_tag(name:"affected", value:"Grafana 2.0.0 through 4.6.3 and 5.0.0 through 5.2.2.");
  script_tag(name:"solution", value:"Update to version 4.6.4 and 5.2.3 respectively.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2018/08/29/grafana-5.2.3-and-4.6.4-released-with-important-security-fix/");

  exit(0);
}

CPE = "cpe:/a:grafana:grafana";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "4.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
