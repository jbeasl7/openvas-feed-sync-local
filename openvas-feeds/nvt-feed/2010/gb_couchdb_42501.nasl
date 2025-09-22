# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100762");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 0.11.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl");
  script_mandatory_keys("apache/couchdb/detected");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a cross-site request-forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue may allow a remote attacker to gain
  unauthorized access to the affected application and perform certain actions in the context of the
  'Futon' administration interface. Other attacks are also possible.");

  script_tag(name:"affected", value:"Apache CouchDB prior to version 0.11.1.");

  script_tag(name:"solution", value:"Update to version 0.11.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42501");
  script_xref(name:"URL", value:"http://wiki.apache.org/couchdb/Breaking_changes");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.11.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.11.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
