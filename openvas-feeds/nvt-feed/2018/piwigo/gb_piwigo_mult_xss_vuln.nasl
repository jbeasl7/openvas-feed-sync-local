# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113128");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-03-08 14:54:00 +0100 (Thu, 08 Mar 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 17:30:00 +0000 (Mon, 26 Mar 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-7722", "CVE-2018-7723", "CVE-2018-7724");

  script_name("Piwigo < 2.9.4 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple stored XSS vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"There are three vulnerabilities:

  - The management panel in Piwigo has stored XSS via the name parameter in a /ws.php request.

  - The management panel in Piwigo has stored XSS via the virtual_name parameter in a /admin.php request.

  - The management panel in Piwigo has stored XSS via the name parameter in a /admin.php?page request.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject arbitrary HTML and JavaScript into the website.");
  script_tag(name:"affected", value:"Piwigo through version 2.9.3.");

  script_tag(name:"solution", value:"Update to version 2.9.4 or later.");

  script_xref(name:"URL", value:"https://github.com/summ3rf/Vulner/blob/master/Piwigo%20Store%20XSS.md");
  script_xref(name:"URL", value:"https://piwigo.org/release-2.9.4");

  exit(0);
}

CPE = "cpe:/a:piwigo:piwigo";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.9.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
