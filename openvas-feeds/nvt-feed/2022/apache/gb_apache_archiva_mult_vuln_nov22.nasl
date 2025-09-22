# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126211");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-11-16 11:01:36 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-17 04:54:00 +0000 (Thu, 17 Nov 2022)");

  script_cve_id("CVE-2022-40308", "CVE-2022-40309");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_http_detect.nasl");
  script_mandatory_keys("apache/archiva/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-40308: Users with write permissions to a repository can delete arbitrary directories.

  - CVE-2022-40309: It's possible to read the database file directly without logging in, when
  anonymous read is enabled");

  script_tag(name:"affected", value:"Apache Archiva prior to version 2.2.9.");

  script_tag(name:"solution", value:"Update to version 2.2.9 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/docs/2.2.9/release-notes.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/1odl4p85r96n27k577jk6ftrp19xfc27");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
