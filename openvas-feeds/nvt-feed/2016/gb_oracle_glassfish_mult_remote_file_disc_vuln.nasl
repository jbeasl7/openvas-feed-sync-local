# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808231");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-06-21 11:16:21 +0530 (Tue, 21 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-21 15:54:00 +0000 (Fri, 21 Jul 2017)");

  script_cve_id("CVE-2017-1000030", "CVE-2017-1000029");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Oracle GlassFish Server Multiple Vulnerabilities (Nov 2016) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("eclipse/glassfish/http/detected");
  script_require_ports("Services/www", 4848);

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to multiple remote file
  disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of user supplied input via 'file' GET parameter in the file system
  API in Oracle GlassFish Server.

  - An unauthenticated access is possible to 'JVM Report page' which will disclose Java Key Store
  password of the admin console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files on the server, to obtain administrative privileged access to the web interface of
  the affected device and to launch further attacks on the affected system.");

  script_tag(name:"affected", value:"GlassFish Server Open Source Edition version 3.0.1 (build 22)
  and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-011/?fid=8037");

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

files = traversal_files();

foreach pattern (keys(files)) {
  url = "/resource/file%3a///" + files[pattern];

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
