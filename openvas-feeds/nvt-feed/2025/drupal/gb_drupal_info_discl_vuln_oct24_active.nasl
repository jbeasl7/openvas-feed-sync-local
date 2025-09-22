# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153923");
  script_version("2025-03-03T06:02:39+0000");
  script_tag(name:"last_modification", value:"2025-03-03 06:02:39 +0000 (Mon, 03 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-03 04:16:09 +0000 (Mon, 03 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 17:38:40 +0000 (Thu, 19 Sep 2024)");

  script_cve_id("CVE-2024-45440");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Information Disclosure Vulnerability (GHSA-mg8j-w93w-xjgc) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_mandatory_keys("drupal/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Drupal is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"core/authorize.php allows full path disclosure (even when error
  logging is None) if the value of hash_salt is file_get_contents of a file that does not exist.");

  script_tag(name:"affected", value:"Drupal version 8.x through 10.2.8, 10.3.x through 10.3.5 and
  11.x through 11.0.4.");

  script_tag(name:"solution", value:"Update to version 10.2.9, 10.3.6, 11.0.5 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-mg8j-w93w-xjgc");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/issues/3457781");
  script_xref(name:"URL", value:"https://senscybersecurity.nl/CVE-2024-45440-Explained/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/core/authorize.php";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (http_vuln_check(port: port, url: url, pattern: ">RuntimeException<", check_header: TRUE,
                    extra_check: "getHashSalt\(\)")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

# nb: No exit(99); as the "hash_salt" variable of settings.php might not be wrongly configured (and
# thus this check isn't reporting which is expected) but the target might be still running an
# affected version.
exit(0);
