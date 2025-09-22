# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147107");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2021-11-05 05:19:06 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 18:55:00 +0000 (Thu, 04 Nov 2021)");

  script_cve_id("CVE-2021-38161");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 8.0.0 < 8.1.3 Certificate Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to missing TSL certificate
  validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper Authentication vulnerability in TLS origin
  verification of Apache Traffic Server allows for man in the middle attacks.");

  script_tag(name:"affected", value:"Apache Traffic Server version 8.0.0 through 8.1.2.");

  script_tag(name:"solution", value:"Update to version 8.1.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/k01797hyncx53659wr3o72s5cvkc3164");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
