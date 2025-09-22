# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortimanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105865");
  script_version("2024-12-18T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-12-18 05:05:50 +0000 (Wed, 18 Dec 2024)");
  script_tag(name:"creation_date", value:"2016-08-12 12:59:41 +0200 (Fri, 12 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-3194", "CVE-2016-3195");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiManager Multiple XSS Vulnerabilities (FG-IR-16-015, FG-IR-16-017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortimanager_consolidation.nasl");
  script_mandatory_keys("fortinet/fortimanager/detected");

  script_tag(name:"summary", value:"Fortinet FortiManager is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-3194: A vulnerability in FortiManager address added page could allow malicious script
  being injected in the input field. This potentially enables XSS attacks.

  - CVE-2016-3195: A client side XSS vulnerability in FortiManager could allow malicious script
  being injected in the Web-UI. This potentially enables XSS attacks.");

  script_tag(name:"affected", value:"Fortinet FortiManager version 5.0.0 through 5.0.11 and 5.2.0
  through 5.2.5.");

  script_tag(name:"solution", value:"Update to version 5.0.12, 5.2.6, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-015");
  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-017");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.12");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6 / 5.4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
