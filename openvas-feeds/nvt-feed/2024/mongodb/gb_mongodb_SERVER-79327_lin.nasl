# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152525");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-02 02:50:17 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-03 14:54:52 +0000 (Wed, 03 Jul 2024)");

  script_cve_id("CVE-2024-6375");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Missing Authorization Check Vulnerability (SERVER-79327) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MongoDB is prone to a missing authorization check
  vulnerability in refine collection shard key.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A command for refining a collection shard key is missing an
  authorization check. This may cause the command to run directly on a shard, leading to either
  degradation of query performance, or to revealing chunk boundaries through timing side
  channels.");

  # nb: 5.1.x through 5.3.x and 6.1.x through 6.3.x are not mentioned as affected in the advisory
  # but are already EOL and thus assumed to be affected as well but just not mentioned by the vendor
  # due to their EOL status.
  script_tag(name:"affected", value:"MongoDB version 5.x prior to 5.0.22, 5.1.x prior to 6.0.11 and
  7.x prior to 7.0.3.");

  script_tag(name:"solution", value:"Update to version 5.0.22, 6.0.11, 7.0.3 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-79327");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.22");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "6.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.11");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "7.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
