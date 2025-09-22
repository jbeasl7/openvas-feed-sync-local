# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127024");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-05-30 11:32:57 +0000 (Mon, 30 May 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-31 23:17:00 +0000 (Tue, 31 May 2022)");

  script_cve_id("CVE-2021-40317");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 13.0.0 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"An attacker might be able to inject and/or alter existing SQL
  statements via the id parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Piwigo prior to version 13.0.0.");

  script_tag(name:"solution", value:"Update to version 13.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/1470");

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

if (version_is_less(version: version, test_version: "13.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
