# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107259");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-11-16 11:20:26 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-12635", "CVE-2017-12636");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache CouchDB 1.x < 1.7.0, 2.x < 2.1.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache CouchDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities are due to differences in the Erlang-based
  JSON parser and JavaScript-based JSON parser.");

  script_tag(name:"impact", value:"These vulnerabilities can be used to give non-admin users access
  to arbitrary shell commands on the server as the database system user.");

  script_tag(name:"affected", value:"Apache CouchDB version 1.x prior to 1.7.0 and 2.x prior to
  2.1.1.");

  script_tag(name:"solution", value:"Update to version 1.7.0, 2.1.1 or later.");

  script_xref(name:"URL", value:"https://blog.couchdb.org/2017/11/14/apache-couchdb-cve-2017-12635-and-cve-2017-12636/");
  script_xref(name:"URL", value:"https://justi.cz/security/2017/11/14/couchdb-rce-npm.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version =~ "^1\.")
{
 if (version_is_less(version: version, test_version: "1.7.0"))
   fix = "1.7.0";
}

else if (version =~ "^2\.")
{
 if (version_is_less(version: version, test_version: "2.1.1"))
   fix = "2.1.1";
}

if (fix)
{
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

