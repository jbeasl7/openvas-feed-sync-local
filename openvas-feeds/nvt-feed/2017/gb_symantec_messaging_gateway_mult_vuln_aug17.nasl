# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140294");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-08-14 10:44:09 +0700 (Mon, 14 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-24 19:57:00 +0000 (Thu, 24 Aug 2017)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-6327", "CVE-2017-6328");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway Multiple Vulnerabilities (Aug 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-6327: The Symantec Messaging Gateway can encounter an issue of remote code execution,
  which describes a situation whereby an individual may obtain the ability to execute commands
  remotely on a target machine or in a target process. In this type of occurrence, after gaining
  access to the system, the attacker may attempt to elevate their privileges.

  - CVE-2017-6328: The Symantec Messaging Gateway can encounter an issue of cross site request
  forgery (also known as one-click attack and is abbreviated as CSRF or XSRF), which is a type of
  malicious exploit of a website where unauthorized commands are transmitted from a user that the
  web application trusts. A CSRF attack attempts to exploit the trust that a specific website has
  in a user's browser.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 10.6.3 and prior.");

  script_tag(name:"solution", value:"Update to version 10.6.3-267 or later.");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170810_00");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "10.6.3"))
  vuln = TRUE;

patch = get_kb_item("symantec/smg/patch");

if (version == "10.6.3") {
  if (patch) {
    if (int(patch) < 267)
      vuln = TRUE;
  } else
    vuln = TRUE;
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, installed_patch: patch,
                            fixed_version: "10.6.3", fixed_patch: "267");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
