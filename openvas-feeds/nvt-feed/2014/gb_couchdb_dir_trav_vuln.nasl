# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105903");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-04-28 11:20:26 +0700 (Mon, 28 Apr 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-5641");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB <= 1.0.3, 1.1.x <= 1.1.1, 1.2.0 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a directory traversal vulnerability in
  the MobchiWeb component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On Windows systems there is a directory traversal vulnerability
  in the partition2 function in mochiweb_util.erl in MochiWeb before 2.4.0, as used in Apache CouchDB
  allows remote attackers to read arbitrary files via a ..\ (dot dot backslash) in the default URI.");

  script_tag(name:"impact", value:"A remote attacker could retrieve in binary form any CouchDB
  database, including the _users or _replication databases, or any other file that the user account
  used to run CouchDB might have read access to on the local filesystem.");

  script_tag(name:"affected", value:"Apache CouchDB version 1.0.3 and prior, 1.1.x through 1.1.1 and
  1.2.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.0.4, 1.1.2, 1.2.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57313");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81240");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jan/81");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version:version, test_version:"1.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if (version_in_range(version:version, test_version:"1.1.0", test_version2:"1.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.1.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if (version_is_equal(version:version, test_version:"1.2.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.2.1", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
