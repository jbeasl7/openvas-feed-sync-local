# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:moxa:eds-40";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106107");
  script_version("2024-02-28T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-02-28 05:05:37 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");

  script_cve_id("CVE-2015-6464", "CVE-2015-6465", "CVE-2015-6466");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa EDS-405A/408A < 3.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_eds_consolidation.nasl");
  script_mandatory_keys("moxa/eds/detected");

  script_tag(name:"summary", value:"Moxa EDS-405A and EDS-408A devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-6464: The administrative web interface on Moxa EDS-405A and EDS-408A switches with
  firmware before 3.6 allows remote authenticated users to bypass a read-only protection mechanism
  by using Firefox with a web-developer plugin.

  - CVE-2015-6465: The GoAhead web server on Moxa EDS-405A and EDS-408A switches with firmware
  before 3.6 allows remote authenticated users to cause a denial of service (reboot) via a crafted
  URL.

  - CVE-2015-6466: Cross-site scripting (XSS) vulnerability in the Diagnosis Ping feature in the
  administrative web interface on Moxa EDS-405A and EDS-408A switches with firmware before 3.6
  allows remote attackers to inject arbitrary web script or HTML via an unspecified field.");

  script_tag(name:"impact", value:"An authenticated attacker may bypass security restrictions or
  cause a denial of service.");

  script_tag(name:"affected", value:"Moxa EDS-405A and EDS-408A prior to version 3.6.");

  script_tag(name:"solution", value:"Update to version 3.6 or later.");

  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=328");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:moxa:eds-40[58]a")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
