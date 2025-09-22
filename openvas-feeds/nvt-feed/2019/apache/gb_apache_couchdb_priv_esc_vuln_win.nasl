# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112476");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-01-03 11:36:11 +0100 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-17188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB < 2.3.0 Remote Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"CouchDB is prone to a remote privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CouchDB allowed for runtime-configuration of key components of the
  database. In some cases, this lead to vulnerabilities where CouchDB admin users could access the
  underlying operating system as the CouchDB user.");

  script_tag(name:"impact", value:"Together with other vulnerabilities, it allowed full system entry
  for unauthenticated users.");

  script_tag(name:"affected", value:"Apache CouchDB version 2.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.0 or later.");

  script_xref(name:"URL", value:"https://blog.couchdb.org/2018/12/17/cve-2018-17188/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "2.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.0", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
