# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pydio:pydio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112712");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2020-03-18 12:44:11 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-20452", "CVE-2019-20453");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pydio Core < 8.2.4 Multiple PHP Object Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_http_detect.nasl");
  script_mandatory_keys("pydio/detected");

  script_tag(name:"summary", value:"Pydio Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-20452: A PHP object injection is present in the page
  plugins/core.access/src/RecycleBinManager.php

  - CVE-2019-20453: A PHP object injection is present in the page
  plugins/uploader.http/HttpDownload.php");

  script_tag(name:"impact", value:"An authenticated user with basic privileges can inject objects
  and achieve remote code execution.");

  script_tag(name:"affected", value:"Pydio Core prior to version 8.2.4.");

  script_tag(name:"solution", value:"Update to version 8.2.4 or later.");

  script_xref(name:"URL", value:"https://pydio.com/en/community/releases/pydio-core/pydio-core-pydio-enterprise-824-security-release");
  script_xref(name:"URL", value:"https://www.certilience.fr/2020/03/cve-2019-20452-vulnerabilite-php-object-injection-pydio-core/");
  script_xref(name:"URL", value:"https://www.certilience.fr/2020/03/cve-2019-20453-vulnerabilite-php-object-injection-pydio-core/");

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

if( version_is_less_equal( version: version, test_version: "8.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
