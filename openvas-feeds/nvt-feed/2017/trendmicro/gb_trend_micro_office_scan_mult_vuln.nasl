# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:officescan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811870");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2017-14083", "CVE-2017-14084", "CVE-2017-14085", "CVE-2017-14086",
                "CVE-2017-14087", "CVE-2017-14088", "CVE-2017-14089");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-02 17:15:23 +0530 (Thu, 02 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Trend Micro OfficeScan Multiple Vulnerabilities (Oct 2017)");

  script_tag(name:"summary", value:"Trend Micro OfficeScan is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check if we are able to access the private key file or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An Unauthorized memory corruption error relate to 'cgiShowClientAdm.exe' file.

  - An improper access control mechanism on sensitive files.

  - Pre-authorization Start Remote Process errors in Micro OfficeScan.

  - Man-in-the-Middle (MitM) attack vulnerabilities.

  - An insufficient validation of user supplied input for 'Host Header'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code and escalate privileges, obtain sensitive
  information and conduct spoofing attack.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan 11.0 SP1 and XG (12.0).");

  script_tag(name:"solution", value:"Upgrade to Trend Micro OfficeScan
  11.0 SP1 CP 6426 or XG (12.0) CP 1708 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101076");
  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1118372");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trend_micro_office_scan_detect_remote.nasl");
  script_mandatory_keys("TrendMicro/OfficeScan/Installed/Remote");
  script_require_ports("Services/www", 443, 4343);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + "/console/RemoteInstallCGI/cgiGetNTDomain.exe";

if(http_vuln_check(port:port, url:url, pattern:'Content-Length:.*',
                    extra_check:make_list('"NODES"', '"NAME"', '"ERROR_CODE"', '"RESPONSE"'),
                    check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
