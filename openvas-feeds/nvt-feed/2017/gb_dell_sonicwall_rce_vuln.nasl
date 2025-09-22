# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:sonicwall:sra";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106980");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-07-24 13:41:24 +0700 (Mon, 24 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-17 10:29:00 +0000 (Wed, 17 Oct 2018)");

  script_cve_id("CVE-2016-9682", "CVE-2016-9683", "CVE-2016-9684");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL Secure Remote Access (SRA) Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_sra_consolidation.nasl");
  script_mandatory_keys("sonicwall/sra_sma/detected");

  script_tag(name:"summary", value:"SonicWall Secure Remote Access is prone to multiple remote
  command execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SonicWall Secure Remote Access is prone to multiple remote command execution
  vulnerabilities:

  - The vulnerability exists in a section of the machine's administrative interface for performing configurations
  related to on-connect scripts to be launched for users's connecting.

  - Two Remote Command Injection vulnerabilities in its web administrative interface. These vulnerabilities occur
  in the diagnostics CGI (/cgi-bin/diagnostics) component responsible for emailing out information about the state
  of the system. (CVE-2016-9682)

  - Remote Command Injection vulnerability in its web administrative interface. This vulnerability occurs in the
  'extensionsettings' CGI (/cgi-bin/extensionsettings) component responsible for handling some of the server's
  internal configurations. (CVE-2016-9683)

  - Remote Command Injection vulnerability in its web administrative interface. This vulnerability occurs in the
  'viewcert' CGI (/cgi-bin/viewcert) component responsible for processing SSL certificate information.
  (CVE-2016-9684)");

  script_tag(name:"impact", value:"An attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Dell SonicWALL SRA versions 8.1.0.2-14sv and prior.");

  script_tag(name:"solution", value:"Upgrade to version 8.1.0.6-21sv or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42343/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "8.1.0.6.21sv")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.0.6-21sv");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
