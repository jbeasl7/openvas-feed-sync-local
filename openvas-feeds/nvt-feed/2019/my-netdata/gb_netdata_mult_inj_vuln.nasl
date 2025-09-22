# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:my-netdata:netdata";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142517");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-06-28 06:30:20 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2018-18836", "CVE-2018-18837", "CVE-2018-18838");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetData < 1.11.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netdata_detect.nasl");
  script_mandatory_keys("netdata/detected");

  script_tag(name:"summary", value:"NetData is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NetData is prone to multiple vulnerabilities:

  - Fixed JSON Header Injection (CVE-2018-18836)

  - Fixed HTTP Header Injection (CVE-2018-18837)

  - Fixed LOG Injection (CVE-2018-18838)

  - Privilege escalation");

  script_tag(name:"affected", value:"NetData version 1.10.0 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.11.0 or later.");

  script_xref(name:"URL", value:"https://github.com/netdata/netdata/releases/tag/v1.11.0");

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

if (version_is_less(version: version, test_version: "1.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
