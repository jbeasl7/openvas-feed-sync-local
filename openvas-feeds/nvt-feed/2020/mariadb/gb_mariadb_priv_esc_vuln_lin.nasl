# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143482");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-02-06 06:09:44 +0000 (Thu, 06 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-12 15:58:00 +0000 (Wed, 12 Feb 2020)");

  script_cve_id("CVE-2020-7221");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB 10.4.7 - 10.4.11 Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mariadb/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"mysql_install_db in MariaDB allows privilege escalation from the mysql user
  account to root because chown and chmod are performed unsafely, as demonstrated by a symlink attack on a chmod
  04755 of auth_pam_tool_dir/auth_pam_tool.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MariaDB versions 10.4.7 - 10.4.11.");

  script_tag(name:"solution", value:"Update to version 10.4.12 or later.");

  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2020/q1/55");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.4.7", test_version2: "10.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.12");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
