# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trihedral:vtscada";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106906");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-23 16:17:12 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-6043", "CVE-2017-6045", "CVE-2017-6053");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VTScada < 11.2.26 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trihedral_vtscada_consolidation.nasl");
  script_mandatory_keys("trihedral/vtscada/detected");

  script_tag(name:"summary", value:"VTScada is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-6043: The client does not properly validate the input or limit the amount of resources
  that are utilized by an attacker, which can be used to consume more resources than are available.

  - CVE-2017-6045: Some files are exposed within the web server application to unauthenticated
  users. These files may contain sensitive configuration information.

  - CVE-2017-6053: A cross-site scripting (XSS) vulnerability may allow JavaScript code supplied by
  the attacker to execute within the user's browser.");

  script_tag(name:"affected", value:"VTScada versions prior to 11.2.26.");

  script_tag(name:"solution", value:"Update to version 11.2.26 or later.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-164-01");

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

if (version_is_less(version: version, test_version: "11.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.2.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
