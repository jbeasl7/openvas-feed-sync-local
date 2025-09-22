# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146931");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-10-18 11:49:15 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-20 15:31:00 +0000 (Wed, 20 Oct 2021)");

  script_cve_id("CVE-2021-38295");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB <= 3.1.1 Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A malicious user with permission to create documents in a
  database is able to attach a HTML attachment to a document. If a CouchDB admin opens that
  attachment in a browser, e.g. via the CouchDB admin interface Fauxton, any JavaScript code
  embedded in that HTML attachment will be executed within the security context of that admin. A
  similar route is available with the already deprecated _show and _list functionality.");

  script_tag(name:"impact", value:"This privilege escalation vulnerability allows an attacker to
  add or remove data in any database or make configuration changes.");

  script_tag(name:"affected", value:"Apache CouchDB version 3.1.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.1.2, 3.2.0 or later.");

  script_xref(name:"URL", value:"https://docs.couchdb.org/en/stable/cve/2021-38295.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.2 / 3.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
