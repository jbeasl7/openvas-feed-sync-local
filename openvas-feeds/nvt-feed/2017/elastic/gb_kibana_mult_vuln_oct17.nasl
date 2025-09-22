# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113010");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-10-09 13:04:33 +0200 (Mon, 09 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:30:00 +0000 (Fri, 14 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-11479");

  script_name("Elastic Kibana <= 5.6.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"The Timelion feature in Elastic Kibana is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the host.");

  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to forge
  GET-parameters and send a malicious link to a user that then performs actions against the host.");

  script_tag(name:"affected", value:"Elastic Kibana versions 5.0.0 through 5.6.0.");

  script_tag(name:"solution", value:"Update to version 5.6.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/x-pack-alerting-and-kibana-5-6-1-security-update/101884");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.6.0" ) ) {
  report = report_fixed_ver(  installed_version: version, fixed_version: "5.6.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
