# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117020");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2020-11-06 10:48:39 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2011-4082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpLDAPadmin < 0.9.8 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_phpldapadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpldapadmin/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A local file inclusion flaw was found in the way the
  phpLDAPadmin processed certain values of the 'Accept-Language' HTTP header.");

  script_tag(name:"impact", value:"A remote attacker could use this flaw to cause a DoS via
  specially-crafted request.");

  script_tag(name:"affected", value:"phpLDAPadmin versions prior to 0.9.8.");

  script_tag(name:"solution", value:"Update to version 0.9.8 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-4082");

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

if (version_is_less(version: version, test_version: "0.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
