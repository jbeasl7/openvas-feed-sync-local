# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106291");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-28 09:42:23 +0700 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2016-2776");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A crafted query could crash the BIND name server daemon, leading to a
  denial of service. All server roles (authoritative, recursive and forwarding) in default configurations are
  affected.");

  script_tag(name:"impact", value:"An remote attacker may cause a denial of service condition.");

  script_tag(name:"solution", value:"Update to 9.9.9-P3, 9.9.9-S5, 9.10.4-P3, 9.11.0rc3 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-01419");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "^9\.9\.[3-9]s[0-9]") {
  if (version_is_less(version: version, test_version: "9.9.9s5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.9-s5", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "9.9.9p3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.9.9-p3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.10.0", test_version2: "9.10.4p2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.10.4-P3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if ((revcomp(a: version, b: "9.11.0a1") >= 0) && (revcomp(a: version, b: "9.11.0rc1") <= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.0rc3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
