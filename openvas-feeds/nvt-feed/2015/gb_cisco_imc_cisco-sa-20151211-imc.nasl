# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:integrated_management_controller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105485");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-12-15 11:41:43 +0100 (Tue, 15 Dec 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2015-6399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Integrated Management Controller Denial of Service Vulnerability (cisco-sa-20151211-imc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_imc_http_detect.nasl");
  script_mandatory_keys("cisco/imc/detected");

  script_tag(name:"summary", value:"A vulnerability in Cisco Integrated Management Controller (IMC)
  could allow an authenticated, remote attacker to make the IMC IP interface inaccessible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete sanitization of input
  for certain parameters. An attacker could exploit this vulnerability by sending a crafted HTTP
  request to the IMC.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the IMC
  to become inaccessible via the IP interface, resulting in a denial of service (DoS) condition.");

  script_tag(name:"affected", value:"Cisco IMC prior to version 2.0(9).");

  script_tag(name:"solution", value:"Update to version 2.0(9) or later.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151211-imc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "\(([0-9A-Za-z.]+)\)", replace: ".\1");

if (version_is_less(version: check_vers, test_version: "2.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0(9)");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
