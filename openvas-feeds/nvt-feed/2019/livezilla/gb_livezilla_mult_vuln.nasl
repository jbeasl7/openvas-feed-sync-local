# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:livezilla:livezilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142530");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-07-02 04:25:13 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-26 10:15:00 +0000 (Wed, 26 Jun 2019)");

  script_cve_id("CVE-2019-12939", "CVE-2019-12940", "CVE-2019-12960", "CVE-2019-12961");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LiveZilla < 8.0.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");

  script_tag(name:"summary", value:"LiveZilla is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LiveZilla is prone to multiple vulnerabilities:

  - Multiple SQL injection vulnerabilities (CVE-2019-12939, CVE-2019-12960)

  - DoS vulnerability (CVE-2019-12940)

  - CSV injection vulnerability (CVE-2019-12961)");

  script_tag(name:"affected", value:"LiveZilla version 8.0.1.0 and probably prior.");

  script_tag(name:"solution", value:"Update to version 8.0.1.1 or later.");

  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10980-fg-vd-19-082-livezilla-server-is-vulnerable-to-sql-injection/");
  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10981-fg-vd-19-084-livezilla-server-is-vulnerable-to-denial-of-service/");
  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10983-fg-vd-19-086-livezilla-server-is-vulnerable-to-sql-injection-ii/");
  script_xref(name:"URL", value:"https://forums.livezilla.net/index.php?/topic/10985-fg-vd-19-088-livezilla-server-is-vulnerable-to-csv-injection/");

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

if (version_is_less(version: version, test_version: "8.0.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
