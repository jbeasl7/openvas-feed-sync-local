# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rips_scanner:rips";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806808");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-01-06 12:48:22 +0530 (Wed, 06 Jan 2016)");
  # nb:
  # - Flaw is from late 2014/early 2015 but the VulnCheck CNA had assigned a 2025 for this so don't
  #   wonder about the huge gap between creation_date and CVE publishing time
  # - It seems the CVE also got assigned for multiple issues, for example the CVE is linking to the
  #   EDB entry 18660 which is from 2012 and for the flaw checked in 2012/gb_rips_lfi_01_12.nasl.
  #   But the CVE is also linking to a blog post from 2015 (linked below) which seems to be about
  #   what is getting checked in here. Due to this the CVE has been added to both VTs for now.
  script_cve_id("CVE-2025-34126");
  script_name("RIPS Scanner 0.55 Multiple LFI Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_rips_http_detect.nasl");
  script_mandatory_keys("rips/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://codesec.blogspot.com/2015/03/rips-scanner-v-054-local-file-include.html");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/rips-scanner-path-traversal");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39094/");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/135066");

  script_tag(name:"summary", value:"RIPS scanner is prone to multiple local file inclusion (LFI)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper validation of user supplied
  input to 'file' parameter in code.php and function.php scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to local php files and to compromise the application.");

  script_tag(name:"affected", value:"RIPS scanner version 0.55 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/windows/function.php?file=leakscan.php&start=0&end=40";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"\./config/securing\.php", extra_check:"securing functions")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
