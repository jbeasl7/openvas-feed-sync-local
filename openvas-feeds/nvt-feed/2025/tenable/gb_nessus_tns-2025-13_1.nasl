# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154861");
  script_version("2025-07-04T05:42:00+0000");
  script_tag(name:"last_modification", value:"2025-07-04 05:42:00 +0000 (Fri, 04 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-03 01:40:48 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-12 13:15:25 +0000 (Thu, 12 Jun 2025)");

  script_cve_id("CVE-2025-6021", "CVE-2025-24855");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Multiple Vulnerabilities (TNS-2025-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities in various
  third-party components (libxml2, libxslt).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.8.5.");

  script_tag(name:"solution", value:"Update to version 10.8.5 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-13");
  script_xref(name:"URL", value:"https://docs.tenable.com/release-notes/Content/nessus/2025.htm#10.8.5");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
