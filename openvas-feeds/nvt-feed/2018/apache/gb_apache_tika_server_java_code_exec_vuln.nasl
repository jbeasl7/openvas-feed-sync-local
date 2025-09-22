# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813537");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-06-20 17:03:55 +0530 (Wed, 20 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 19:17:00 +0000 (Wed, 19 Aug 2020)");

  script_cve_id("CVE-2016-6809");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika 1.9 - 1.13 Java Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to an arbitrary Java code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Apache Tika invoking JMatIO to do native
  deserialization.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary Java code for serialized objects embedded in MATLAB files.");

  script_tag(name:"affected", value:"Apache Tika version 1.6 through 1.13.");

  script_tag(name:"solution", value:"Update to version 1.14 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/93618b15cdf3b38fa1f0bfc0c8c7cf384607e552935bd3db2e322e07@%3Cdev.tika.apache.org%3E");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.6", test_version2: "1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
