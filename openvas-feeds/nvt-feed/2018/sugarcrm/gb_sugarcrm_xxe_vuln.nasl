# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113111");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-02-14 10:40:00 +0100 (Wed, 14 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 16:23:00 +0000 (Thu, 15 Feb 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-3244");

  script_name("SugarCRM <= 6.5.16 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_http_detect.nasl");
  script_mandatory_keys("sugarcrm/detected");

  script_tag(name:"summary", value:"SugarCRM is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists within the RSSDashlet dashlet.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to read arbitrary
  files or potentially execute arbitrary code via a crafted DTD in an XML request.");

  script_tag(name:"affected", value:"SugarCRM through version 6.5.16.");

  script_tag(name:"solution", value:"Update to version 6.5.17.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/92");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68102");
  script_xref(name:"URL", value:"https://web.archive.org/web/20151105182132/http://www.pnigos.com/?p=294");

  exit(0);
}

CPE = "cpe:/a:sugarcrm:sugarcrm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "6.5.17" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.17" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
