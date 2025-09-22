# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113127");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-03-08 13:45:55 +0100 (Thu, 08 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-02 23:19:00 +0000 (Fri, 02 Dec 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-7452", "CVE-2016-7453");

  script_name("Exponent CMS 2.3.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_mandatory_keys("ExponentCMS/installed");

  script_tag(name:"summary", value:"ExponentCMS is prone to multiple vulnerabilities that have their source in the Pixidou Image Editor component.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"There are two vulnerabilities:

  The Pixidou Image Editor in Exponent CMS could be used to upload a malicious file to any folder on the site via a cpi directory traversal.

  The Pixidou Image Editor in Exponent CMS could be used to perform an fid SQL Injection.");
  script_tag(name:"affected", value:"Exponent CMS through version 2.3.9.");
  script_tag(name:"solution", value:"Update to version 2.4.0.");

  script_xref(name:"URL", value:"https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93045");

  exit(0);
}

CPE = "cpe:/a:exponentcms:exponent_cms";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.4.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
