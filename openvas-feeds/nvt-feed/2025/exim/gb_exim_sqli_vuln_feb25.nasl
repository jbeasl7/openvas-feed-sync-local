# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154064");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-24 02:53:24 +0000 (Mon, 24 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-26794");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.98 < 4.98.1 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim, when SQLite hints and ETRN serialization are used, allows
  remote SQL injection.");

  script_tag(name:"affected", value:"Exim version 4.98.");

  script_tag(name:"solution", value:"Update to version 4.98.1 or later.");

  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2025-26794.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "4.98", test_version_up: "4.98.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.98.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
