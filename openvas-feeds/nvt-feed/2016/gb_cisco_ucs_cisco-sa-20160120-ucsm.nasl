# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105526");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-01-25 15:34:07 +0100 (Mon, 25 Jan 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)");

  script_cve_id("CVE-2015-6435");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Computing System Manager Remote Command Execution Vulnerability (cisco-sa-20160120-ucsm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/detected");

  script_tag(name:"summary", value:"A vulnerability in a CGI script in the Cisco Unified Computing
  System (UCS) Manager could allow an unauthenticated, remote attacker to execute arbitrary
  commands on the Cisco UCS Manager.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to unprotected calling of shell
  commands in the CGI script. An attacker could exploit this vulnerability by sending a crafted
  HTTP request to the Cisco UCS Manager.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary
  commands on the Cisco UCS Manager.");

  script_tag(name:"affected", value:"Cisco UCS Manager version 2.2.x.");

  script_tag(name:"solution", value:"Update to version 2.2(4b), 2.2(5a), 2.2(6a), 3.0(2e), 3.1(e)
  or later.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160120-ucsm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

vers = eregmatch(pattern: "^([0-9.]+)\(([^)]+)\)", string: version);
if (isnull(vers[1]) || isnull(vers[2]))
  exit(0);

major = vers[1];
build = vers[2];

if (version_is_less(version: major, test_version: "2.2"))
  exit(99);

if (major =~ "^2\.2") {
 if (build =~ "^[1-3]")
   fix = "2.2(4b)";

 if (build =~ "^4($|a)")
   fix = "2.2(4b)";

 if (build =~ "^5$")
   fix = "2.2(5a)";

 if (build =~ "^6$")
   fix = "2.2(6a)";
}

if (major =~ "^3\.0") {
  if (build =~ "^[01]")
    fix = "3.0(2e)";

  if (build =~ "^2[a-d]")
    fix = "3.0(2e)";
}

if (major =~ "^3\.1") {
  if (build =~ "^($|[a-d])")
    fix = "3.1(e)";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
