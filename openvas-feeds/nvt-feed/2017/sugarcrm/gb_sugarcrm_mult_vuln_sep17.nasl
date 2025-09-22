# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sugarcrm:sugarcrm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140402");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-09-26 13:58:02 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-30 02:29:00 +0000 (Sat, 30 Dec 2017)");

  script_cve_id("CVE-2017-14508", "CVE-2017-14509", "CVE-2017-14510");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SugarCRM Multiple Vulnerabilities (Sep 2017)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_http_detect.nasl");
  script_mandatory_keys("sugarcrm/detected");

  script_tag(name:"summary", value:"SugarCRM is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"SugarCRM is prone to multiple vulnerabilities:

  - Authenticated users may cause arbitrary SQL to be executed. (CVE-2017-14508)

  - Authenticated users may access system files. (CVE-2017-14509)

  - Unauthenticated users may cause arbitrary code to be executed. (CVE-2017-14510)");

  script_tag(name:"affected", value:"SugarCRM version 7.7, 7.8 and 7.9.");

  script_tag(name:"solution", value:"Update to version 7.7.2.3, 7.8.2.2, 7.9.2.0 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-006/");
  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-007/");
  script_xref(name:"URL", value:"https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2017-008/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^7\.7\.") {
  if (version_is_less(version: version, test_version: "7.7.2.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.7.2.3");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^7\.8\.") {
  if (version_is_less(version: version, test_version: "7.8.2.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.8.2.2");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^7\.9\.") {
  if (version_is_less(version: version, test_version: "7.9.2.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.9.2.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
