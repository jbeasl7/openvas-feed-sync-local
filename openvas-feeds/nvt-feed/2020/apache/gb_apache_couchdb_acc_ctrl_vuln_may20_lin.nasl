# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112757");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-05-25 13:22:00 +0000 (Mon, 25 May 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-22 17:30:00 +0000 (Fri, 22 May 2020)");

  script_cve_id("CVE-2020-1955");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache CouchDB 3.0.0 Remote Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"CouchDB  is prone to a remote privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CouchDB version 3.0.0 shipped with a new configuration setting
  that governs access control to the entire database server called require_valid_user_except_for_up.
  It was meant as an extension to the long-standing setting require_valid_user, which in turn requires
  that any and all requests to CouchDB will have to be made with valid credentials, effectively
  forbidding any anonymous requests.

  The new require_valid_user_except_for_up is an off-by-default setting that was meant to allow
  requiring valid credentials for all endpoints except for the /_up endpoint.

  However, the implementation of this made an error that lead to not enforcing credentials on any
  endpoint, when enabled.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to escalate his
  privileges.");

  script_tag(name:"affected", value:"Apache CouchDB version 3.0.0.");

  script_tag(name:"solution", value:"Update to version 3.0.1, 3.1.0 or later.");

  script_xref(name:"URL", value:"https://docs.couchdb.org/en/master/cve/2020-1955.html");

  exit(0);
}

CPE = "cpe:/a:apache:couchdb";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version: vers, test_version: "3.0.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.0.1 / 3.1.0", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
