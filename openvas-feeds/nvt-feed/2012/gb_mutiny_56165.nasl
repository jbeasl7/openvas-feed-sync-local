# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mutiny:standard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103589");
  script_cve_id("CVE-2012-3001");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("2024-03-04T14:37:58+0000");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mutiny Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56165");

  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-10-23 10:29:30 +0200 (Tue, 23 Oct 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_mutiny_detect.nasl");
  script_mandatory_keys("Mutiny/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Mutiny is prone to a command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands with root privileges.

Mutiny versions prior to 4.5-1.12 are vulnerable.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less(version:vers, test_version:"4.5-1.12")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.5-1.12");
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
