# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:coturn:coturn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141942");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-01-30 14:14:23 +0700 (Wed, 30 Jan 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:18:00 +0000 (Tue, 07 Jun 2022)");

  script_cve_id("CVE-2018-4056", "CVE-2018-4058", "CVE-2018-4059");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("coturn <= 4.5.0.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_coturn_http_detect.nasl");
  script_mandatory_keys("coturn/detected");

  script_tag(name:"summary", value:"coturn is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"coturn is prone to multiple vulnerabilities:

  - Administrator web portal SQL injection vulnerability (CVE-2018-4056)

  - Unsafe loopback forwarding default configuration vulnerability (CVE-2018-4058)

  - Unsafe telnet admin portal default configuration vulnerability (CVE-2018-4059)");

  script_tag(name:"affected", value:"coturn before version 4.5.0.9.");

  script_tag(name:"solution", value:"Update to version 4.5.0.9 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2019/01/vulnerability-spotlight-multiple.html");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2018-0730");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2018-0723");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2018-0733");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
