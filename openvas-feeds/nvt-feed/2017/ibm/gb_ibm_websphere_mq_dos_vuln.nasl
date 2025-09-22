# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113066");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-12-08 14:11:12 +0100 (Fri, 08 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1433");

  script_name("IBM WebSphere MQ 7.5, 8.0 and 9.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_detect.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ 7.5, 8.0, and 9.0 could allow an authenticated user to insert
  messages with a corrupt RFH header into the channel which would cause it to restart.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"IBM WebSphere MQ 7.5.0.0 through 7.5.0.8, 8.0.0.0 through 8.0.0.7 and 9.0.0.0
  through 9.0.0.1.");

  script_tag(name:"solution", value:"Update IBM WebSphere MQ to 8.0.0.8 or 9.0.0.2 respectively. For 7.5.0.X,
  apply interim fix for APAR IT15943.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22005525");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/127803");

  exit(0);
}

CPE = "cpe:/a:ibm:websphere_mq";

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version: version, test_version: "7.5.0.0", test_version2: "7.5.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.5.0.8-IT15943", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.0.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.0.8", install_path: path );
  security_message(port: port, data: report);
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.0.0", test_version2: "9.0.0.1" ) ) {
  report = report_fixed_ver ( installed_version: version, fixed_version: "9.0.0.2", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
