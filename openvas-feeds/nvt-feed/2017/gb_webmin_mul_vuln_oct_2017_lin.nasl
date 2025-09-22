# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107249");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-15644", "CVE-2017-15645", "CVE-2017-15646");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 20:28:00 +0000 (Tue, 07 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-10-16 12:05:05 +0530 (Mon, 16 Oct 2017)");
  script_name("Webmin Multiple Vulnerabilities - Linux");

  script_tag(name:"summary", value:"Webmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check for vulnerable version.");

  script_tag(name:"insight", value:"Webmin echo back the 'File Download' request
  status which we can trigger the XSS vulnerability and bypass this Referrer check
  by setting the domain=webmin-victim-ip. User controlled input is not sufficiently
  sanitized which can lead to CSRF and Server side Request Forgery.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to perform the following attacks:

  - XSS vulnerability that leads to Remote Code Execution

  - CSRF Schedule arbitrary commands

  - Server Side Request Forgery.");

  script_tag(name:"affected", value:"Webmin version prior to 1.860");

  script_tag(name:"solution", value:"Upgrade to webmin version 1.860");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3430");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/0c58892732ee7610a7abba5507614366d382c9c9");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.webmin.com/security.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!Port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
 exit(0);
}

if(version_is_less(version:Ver, test_version:"1.860"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"1.860");
  security_message(data:report, port:Port);
  exit(0);
}

exit(0);
