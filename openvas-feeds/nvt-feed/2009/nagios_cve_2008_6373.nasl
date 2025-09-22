# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100188");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
  script_cve_id("CVE-2008-6373");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios External Commands and Adaptive Commands Unspecified Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"solution", value:"The vendor has released updates.");

  script_tag(name:"summary", value:"Nagios is prone to an unspecified vulnerability related to the CGI
  submission of external commands and the processing of adaptive commands.

  The issue affects versions prior to Nagios 3.0.6.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32611");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "3.0.6")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.0.6");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
