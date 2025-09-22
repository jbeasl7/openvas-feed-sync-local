# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jquery:jquery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142314");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-04-25 15:17:31 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2019-5428", "CVE-2019-11358");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patches for lower versions available and likely to be applied

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("jQuery < 3.4.0 Object Extensions Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jquery_consolidation.nasl");
  script_mandatory_keys("jquery/detected");

  script_tag(name:"summary", value:"jQuery is prone to multiple vulnerabilities regarding property
  injection in Object.prototype.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-5428: A prototype pollution vulnerability exists that allows an attacker to inject
  properties on Object.prototype.

  - CVE-2019-11358: jQuery mishandles jQuery.extend(true, {}, ...) because of Object.prototype
  pollution. If an unsanitized source object contained an enumerable __proto__ property, it could
  extend the native Object.prototype.");

  script_tag(name:"affected", value:"jQuery prior to version 3.4.0.");

  script_tag(name:"solution", value:"Update to version 3.4.0 or later. Patch diffs are available for
  older versions.");

  script_xref(name:"URL", value:"https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/");
  script_xref(name:"URL", value:"https://github.com/DanielRuf/snyk-js-jquery-174006?files=1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.0", install_path: location);

  extra_reporting = get_kb_item("jquery/http/" + port + "/" + location + "/extra_reporting");
  if (extra_reporting)
    report += '\nDetection info (see OID: 1.3.6.1.4.1.25623.1.0.150658 for more info):\n' + extra_reporting;

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
