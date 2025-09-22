# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106789");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-25 13:31:59 +0200 (Tue, 25 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");

  script_cve_id("CVE-2017-5659", "CVE-2016-5396");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Traffic Server is prone to multiple vulnerabilities:

  - Crash when there is a mismatch between content length and chunked encoding. (CVE-2017-5659)

  - Vulnerable to HPACK Bomb Attack (CVE-2016-5396)");

  script_tag(name:"affected", value:"Apache Traffic Server 6.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-4819");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-5019");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
