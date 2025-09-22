# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortiweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105205");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1955", "CVE-2014-1956", "CVE-2014-1957");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiWeb Multiple Vulnerabilities (FG-IR-13-009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortiweb_consolidation.nasl");
  script_mandatory_keys("fortinet/fortiweb/detected");

  script_tag(name:"summary", value:"Fortinet FortiWeb is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-1955: cross-site scripting (XSS)

  - CVE-2014-1956: HTTP header injection

  - CVE-2014-1957: privilege escalation");

  script_tag(name:"impact", value:"A remote unauthenticated attacker may be able to execute
  arbitrary JavaScript in the context of the administrator's browser session. In addition,
  authenticated users may be able to escalate their privileges.");

  script_tag(name:"affected", value:"Fortinet FortiWeb version 4.4.7 and prior and 5.0.0 through
  5.0.2.");

  script_tag(name:"solution", value:"Update to version 5.0.3 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-13-009");
  script_xref(name:"Advisory-ID", value:"FG-IR-13-009");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
