# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100365");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)");
  script_cve_id("CVE-2009-4112");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti 'Linux - Get Memory Usage' RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37137");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-11/0292.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_cacti_http_detect.nasl");
  script_mandatory_keys("cacti/detected");

  script_tag(name:"summary", value:"Cacti is prone to a remote command-execution vulnerability because the
  software fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected software and possibly the host.");

  script_tag(name:"solution", value:"Update to version 0.8.7e or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "0.8.7e")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.8.7e");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
