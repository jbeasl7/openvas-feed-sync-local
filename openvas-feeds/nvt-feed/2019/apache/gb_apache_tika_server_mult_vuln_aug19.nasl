# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112618");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2019-08-05 13:18:12 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-10088", "CVE-2019-10094");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika 1.7 < 1.22 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-10088: A carefully crafted or corrupt zip file can cause an OOM in Apache Tika's
  RecursiveParserWrapper

  - CVE-2019-10094: A carefully crafted package/compressed file that, when unzipped/uncompressed
  yields the same file (a quine), causes a StackOverflowError in Apache Tika's
  RecursiveParserWrapper");

  script_tag(name:"affected", value:"Apache Tika version 1.7 through 1.21.");

  script_tag(name:"solution", value:"Update to version 1.22 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/1c63555609b737c20d1bbfa4a3e73ec488e3408a84e2f5e47e1b7e08@%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/fe876a649d9d36525dd097fe87ff4dcb3b82bb0fbb3a3d71fb72ef61@%3Cdev.tika.apache.org%3E");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.7", test_version2: "1.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.22");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
