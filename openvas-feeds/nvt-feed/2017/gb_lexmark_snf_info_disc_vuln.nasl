# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140358");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-09-06 08:42:19 +0700 (Wed, 06 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 17:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2017-13771");

  script_tag(name:"qod_type", value:"exploit");

  script_name("Lexmark Scan To Network Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/http/detected");

  script_tag(name:"summary", value:"Lexmark Scan to Network <= 3.2.9 is prone to an information disclosure
  vulnerability.");

  script_tag(name:"insight", value:"Scan To Network application supports the configuration of network
  credentials and if used they will be stored in plaintext and transmitted in every request to the configuration tab.
  It is possible to obtain these credentials which could be used later to escalate privileges in the network or
  get access to scanned documents.");

  script_tag(name:"vuldetect", value:"Sends a HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Aug/46");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/cgi-bin/direct/printer/prtappauth/apps/ImportExportServlet?exportButton=clicked';

if (http_vuln_check(port: port, url: url, pattern: 'cifs.pwd "', check_header: TRUE,
                    extra_check: 'cifs.uName "')) {
  report = "It was possible to obtain network credentials over the following url:\n\n" +
           http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
