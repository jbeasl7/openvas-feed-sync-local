# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106937");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-11 11:31:58 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3143");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_tag(name:"summary", value:"A flaw was found in the way BIND handled TSIG authentication for dynamic
  updates. A remote attacker able to communicate with an authoritative BIND server could use this flaw to
  manipulate the contents of a zone, by forging a valid TSIG or SIG(0) signature for a dynamic update request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ISC BIND versions 9.4.0-9.8.8, 9.9.0-9.9.10-P1, 9.10.0-9.10.5-P1,
  9.11.0-9.11.1-P1, 9.9.3-S1-9.9.10-S2 and 9.10.5-S1-9.10.5-S2");

  script_tag(name:"solution", value:"Update to version 9.9.10-P2, 9.10.5-P2, 9.11.1-P2, 9.9.10-S3, 9.10.5-S3
  or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01503");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version =~ "^9\.(9|10)\.[0-9]+s[0-9]") {
  if (version_is_less(version: version, test_version: "9.9.10s3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.10-S3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.5s1", test_version2: "9.10.5s2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.5-S3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}
else {
  if (version_in_range(version: version, test_version: "9.4.0", test_version2: "9.8.8") ||
      version_in_range(version: version, test_version: "9.9.0", test_version2: "9.9.10p1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.10-P2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.0", test_version2: "9.10.5p1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.5-P2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.11.0", test_version2: "9.11.1p1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.1-P2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
