# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pureftpd:pure-ftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124901");
  script_version("2025-07-15T05:43:27+0000");
  script_tag(name:"last_modification", value:"2025-07-15 05:43:27 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-09 07:35:08 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_cve_id("CVE-2024-48208");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pure-FTPd < 1.0.52 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("sw_pure-ftpd_detect.nasl");
  script_mandatory_keys("pure-ftpd/detected");

  script_tag(name:"summary", value:"Pure-FTPd is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is an out of bounds read in the domlsd() function of the
  ls.c file.");

  script_tag(name:"affected", value:"Pure-FTPd prior to version 1.0.52.");

  script_tag(name:"solution", value:"Update to version 1.0.52 or later.");

  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/pull/176");
  script_xref(name:"URL", value:"https://github.com/jedisct1/pure-ftpd/blob/1.0.52/ChangeLog#L6-L7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.0.52")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.52");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
