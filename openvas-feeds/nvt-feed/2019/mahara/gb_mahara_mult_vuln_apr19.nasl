# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112572");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2019-05-08 11:04:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-9708", "CVE-2019-9709");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara 17.10 < 17.10.8, 18.04 < 18.04.4, 18.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-9708: A site administrator can suspend the system user (root), causing all users to be
  locked out from the system.

  - CVE-2019-9709: The collection title is vulnerable to cross-site scripting (XSS) due to not
  escaping it when viewing the collection's SmartEvidence overview page (if that feature is turned
  on). This can be exploited by any logged-in user.");

  script_tag(name:"affected", value:"Mahara version 17.10 prior to 17.10.8, 18.04 prior to 18.04.4
  and 18.10 prior to 18.10.1.");

  script_tag(name:"solution", value:"Update to version 17.10.8, 18.04.4 or 18.10.1 or later.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1819547");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8446");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1817221");
  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8445");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( !port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "17.10", test_version2: "17.10.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "17.10.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "18.04", test_version2: "18.04.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.04.4", install_path: location );
  security_message(  port: port, data: report );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "18.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.10.1", install_path: location );
  security_message(  port: port, data: report );
  exit( 0 );
}

exit( 99 );
