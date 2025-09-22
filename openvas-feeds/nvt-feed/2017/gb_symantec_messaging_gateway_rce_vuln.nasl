# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106862");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-06-12 10:11:59 +0700 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6324", "CVE-2017-6325", "CVE-2017-6326");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway <= 10.6.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-6324: The Symantec Messaging Gateway, when processing a specific email attachment, can
  allow a malformed or corrupted Word file with a potentially malicious macro through despite the
  administrator having the 'disarm' functionality enabled. This constitutes a 'bypass' of the
  disarm functionality resident to the application.

  - CVE-2017-6325: The Symantec Messaging Gateway can encounter a file inclusion vulnerability,
  which is a type of vulnerability that is most commonly found to affect web applications that rely
  on a scripting run time. This issue is caused when an application builds a path to executable
  code using an attacker-controlled variable in a way that allows the attacker to control which
  file is executed at run time. This file inclusion vulnerability subverts how an application loads
  code for execution. Successful exploitation of a file inclusion vulnerability will result in
  remote code execution on the web server that runs the affected web application.

  - CVE-2017-6326: The Symantec Messaging Gateway can encounter an issue of remote code execution,
  which describes a situation whereby an individual may obtain the ability to execute commands
  remotely on a target machine or in a target process.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 10.6.3 and prior.");

  script_tag(name:"solution", value:"Update to version 10.6.3-266 or later.");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170621_00");

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
    if (int(patch) < 266)
      vuln = TRUE;
  } else
    vuln = TRUE;
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, installed_patch: patch,
                            fixed_version: "10.6.3", fixed_patch: "266");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
