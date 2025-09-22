# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128052");
  script_version("2024-09-20T15:39:53+0000");
  script_tag(name:"last_modification", value:"2024-09-20 15:39:53 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-17 10:00:00 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-30 13:07:46 +0000 (Fri, 30 Aug 2024)");

  script_cve_id("CVE-2024-8207");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Server Library Local Privilege Escalation Vulnerability (SERVER-69507) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In certain highly specific configurations of the host system and
  MongoDB server binary installation on Linux Operating Systems, it may be possible for a unintended
  actor with host-level access to cause the MongoDB Server binary to load unintended
  actor-controlled shared libraries when the server binary is started, potentially resulting in the
  unintended actor gaining full control over the MongoDB server process.");

  script_tag(name:"affected", value:"MongoDB version 5.0.0 through 5.0.13, 6.0.0 through 6.0.2 and 6.1.0.");

  script_tag(name:"solution", value:"Update to version 5.0.14, 6.0.3, 6.1.1 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-69507");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1.0", test_version_up: "6.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);