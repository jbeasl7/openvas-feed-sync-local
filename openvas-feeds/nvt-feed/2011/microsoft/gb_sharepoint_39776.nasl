# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: The banner set by the relevant detection should be always there for the affected systems...
CPE = "cpe:/a:microsoft:sharepoint_team_services";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103254");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0817");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SharePoint Server 2007 XSS Vulnerability (MS10-039) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("microsoft_windows_sharepoint_services_http_detect.nasl");
  script_mandatory_keys("microsoft/windows_sharepoint_team_services/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Microsoft SharePoint Server 2007 and SharePoint Services 3.0 are
  prone to a cross-site scripting (XSS) vulnerability because they fail to properly sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution", value:"The vendor has released an advisory and updates. Please see the
  references for details.");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-039");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/blog/2010/04/security-advisory-983438-released/");
  script_xref(name:"URL", value:"https://support.avaya.com/css/public/documents/100089744");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121052052/http://www.securityfocus.com/archive/1/511021");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/12450");
  script_xref(name:"URL", value:"https://www.immuniweb.com/advisory/HTB22350");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127220432/http://www.securityfocus.com/bid/39776");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/_layouts/help.aspx?cid0=MS.WSS.manifest.xml%00%3Cscript%3Ealert%28%27VT-XSS-Test%27%29%3C/script%3E&tid=X";

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('VT-XSS-Test'\)</script><br/>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
