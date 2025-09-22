# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaltura:kaltura";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140397");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-09-26 10:46:06 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-27 02:29:00 +0000 (Sat, 27 Jan 2018)");

  script_cve_id("CVE-2017-14141", "CVE-2017-14142", "CVE-2017-14143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kaltura Server < 13.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kaltura_http_detect.nasl");
  script_mandatory_keys("kaltura/detected");

  script_tag(name:"summary", value:"Kaltura Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-14141: Authenticated remote code dxecution (RCE) through unserialize() in the admin
  panel

  - CVE-2017-14142: Multiple cross-site scripting (XSS) vulnerabilities under the API path

  - CVE-2017-14143: Unauthenticated RCE through unserialize() from cookie data");

  script_tag(name:"affected", value:"Kaltura Server 13.1.0 and prior.");

  script_tag(name:"solution", value:"Update to version 13.2.0 or later.");

  script_xref(name:"URL", value:"https://telekomsecurity.github.io/assets/advisories/20170912_kaltura-advisory.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "13.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
