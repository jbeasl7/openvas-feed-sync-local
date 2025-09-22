# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112684");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-01-09 08:28:27 +0000 (Thu, 09 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 19:39:00 +0000 (Tue, 10 Nov 2020)");

  script_cve_id("CVE-2019-20363", "CVE-2019-20364", "CVE-2019-20365", "CVE-2019-20366");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openfire 4.3.x < 4.5.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/detected");

  script_tag(name:"summary", value:"Openfire is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist in various parameters of the application.");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker to inject
  arbitrary script commands into the affected application.");

  script_tag(name:"affected", value:"Openfire versions 4.3.x through 4.4.x.");

  script_tag(name:"solution", value:"Update to version 4.5.0 or later.");

  script_xref(name:"URL", value:"https://issues.igniterealtime.org/browse/OF-1955");
  script_xref(name:"URL", value:"https://github.com/igniterealtime/Openfire/pull/1561");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "4.3", test_version2: "4.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.5.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
