# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112318");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2017-6487", "CVE-2017-6488", "CVE-2017-6489", "CVE-2017-6490", "CVE-2017-6491");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-04 18:07:00 +0000 (Tue, 04 Jan 2022)");
  script_tag(name:"creation_date", value:"2018-06-29 10:55:00 +0200 (Fri, 29 Jun 2018)");
  script_name("EPESI <= 1.8.1.1 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_epesi_detect.nasl");
  script_mandatory_keys("epesi/installed");

  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96586");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96955");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/166");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/167");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/168");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/169");

  script_tag(name:"summary", value:"EPESI is prone to multiple cross-site scripting (XSS) vulnerabilities in various parameters.");

  script_tag(name:"affected", value:"EPESI up to and including version 1.8.1.1.");

  script_tag(name:"solution", value:"Update to EPESI version 1.8.2 (rev20170430) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:telaxus:epesi";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less(version:vers, test_version:"1.8.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
