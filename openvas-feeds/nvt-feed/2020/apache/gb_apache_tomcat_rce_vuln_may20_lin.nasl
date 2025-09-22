# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143963");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-05-25 09:00:31 +0000 (Mon, 25 May 2020)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-9484");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat RCE Vulnerability (May 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"If:

  - an attacker is able to control the contents and name of a file on the server and

  - the server is configured to use the PersistenceManager with a FileStore and

  - the PersistenceManager is configured with sessionAttributeValueClassNameFilter='null' (the default unless a
    SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be
    deserialized and

  - the attacker knows the relative file path from the storage location used by FileStore to the file the
    attacker has control over

  then, using a specifically crafted request, the attacker will be able to trigger remote code execution via
  deserialization of the file under their control. Note that all of conditions must be true for the attack to
  succeed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 7.0.0 to 7.0.103, 8.5.0 to 8.5.54, 9.0.0.M1 to 9.0.34 and
  10.0.0-M1 to 10.0.0-M4.");

  script_tag(name:"solution", value:"Update to version 7.0.104, 8.5.55, 9.0.35, 10.0.0-M5 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r77eae567ed829da9012cadb29af17f2df8fa23bf66faf88229857bb1%40%3Cannounce.tomcat.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.103")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.104", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.54")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.55", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.34") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0.M1") >= 0) && (revcomp(a: version, b: "10.0.0.M4") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0-M5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
