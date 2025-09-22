# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100925");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_cve_id("CVE-2010-4367", "CVE-2010-4368");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Awstats < 7.0 Configuration File Remote Arbitrary Command Execution Vulnerability");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/870532");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127132815/http://www.securityfocus.com/bid/45123");
  script_xref(name:"URL", value:"http://www.exploitdevelopment.com/Vulnerabilities/2010-WEB-001.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_awstats_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("awstats/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Awstats is prone to an arbitrary command-execution vulnerability. This issue
  is due to a failure in the application to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to execute arbitrary shell commands
  in the context of the webserver process. This may help attackers compromise the underlying system. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"Awstats versions prior to 7.0 when installed on Apache Tomcat
  on Microsoft Windows operating systems.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "6.95")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
