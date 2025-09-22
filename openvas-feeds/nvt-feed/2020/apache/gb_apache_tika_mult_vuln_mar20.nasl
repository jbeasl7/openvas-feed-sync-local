# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113657");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2020-03-24 12:14:24 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_cve_id("CVE-2020-1950", "CVE-2020-1951");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika 1.x <= 1.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A carefully crafted or corrupt PSD file can cause excessive memory usage in the PSDParser.

  - A carefully crafted or corrupt PSD file can cause an infinite loop in the PSDParser.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the
  application or exhaust the target system's resources.");

  script_tag(name:"affected", value:"Apache Tika version 1.0 through 1.23.");

  script_tag(name:"solution", value:"Update to version 1.24 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r463b1a67817ae55fe022536edd6db34e8f9636971188430cbcf8a8dd%40%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/rd8c1b42bd0e31870d804890b3f00b13d837c528f7ebaf77031323172%40%3Cdev.tika.apache.org%3E");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.24");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
