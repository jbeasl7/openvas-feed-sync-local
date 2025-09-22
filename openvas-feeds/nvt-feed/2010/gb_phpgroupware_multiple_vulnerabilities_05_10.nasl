# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100640");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_cve_id("CVE-2010-0403", "CVE-2010-0404");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("phpGroupWare Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40167");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpGroupWare/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released phpGroupWare 0.9.16.016 to address this issue.
  Please see the references for more information.");

  script_tag(name:"summary", value:"phpGroupWare is prone to multiple SQL-injection vulnerabilities and
  to a Local File Include Vulnerability because it fails to sufficiently
  sanitize user-supplied data before using it.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, exploit latent vulnerabilities
  in the underlying database or to view files and execute local scripts
  in the context of the webserver process.");

  script_tag(name:"affected", value:"Versions of phpGroupWare prior to 0.9.16.016 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(vers = get_version_from_kb(port:port,app:"phpGroupWare")) {
  if(version_is_less(version: vers, test_version: "0.9.16.016")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.16.016");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
