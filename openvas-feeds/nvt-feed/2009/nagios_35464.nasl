# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100229");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-08 19:01:22 +0200 (Wed, 08 Jul 2009)");
  script_cve_id("CVE-2009-2288");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios 'statuswml.cgi' Remote Arbitrary Shell Command Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"solution", value:"The vendor has released updates.");

  script_tag(name:"summary", value:"Nagios is prone to a remote command-injection vulnerability because
  it fails to adequately sanitize user-supplied input data.

  Remote attackers can exploit this issue to execute arbitrary shell
  commands with the privileges of the user running the application.

  Note that for an exploit to succeed, access to the WAP interface's
  ping feature must be allowed.

  Versions prior to Nagios 3.1.1 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35464");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "3.1.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.1.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
