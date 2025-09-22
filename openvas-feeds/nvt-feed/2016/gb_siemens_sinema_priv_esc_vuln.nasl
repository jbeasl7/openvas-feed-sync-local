# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:siemens:sinema_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106221");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-09-02 14:50:41 +0700 (Fri, 02 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:33:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-6486");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Siemens SINEMA Server Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_siemens_sinema_server_detect.nasl");
  script_mandatory_keys("sinema_server/detected");

  script_tag(name:"summary", value:"SINEMA Server is affected by a vulnerability that could allow
  authenticated operating system users to escalate their privileges.");

  script_tag(name:"insight", value:"The file permissions set for the SINEMA Server application folder could
  allow users, authenticated via the operating system, to escalate their privileges.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow users,
  authenticated via the operating system, to escalate their privileges under certain conditions.");

  script_tag(name:"affected", value:"SINEMA Server V13 and prior.");

  script_tag(name:"solution", value:"Siemens provides a temporary fix for existing installations through
  its local service organization.");

  script_xref(name:"URL", value:"http://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-321174.pdf");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-215-02");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

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

if (version_is_less_equal(version: version, test_version: "13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
