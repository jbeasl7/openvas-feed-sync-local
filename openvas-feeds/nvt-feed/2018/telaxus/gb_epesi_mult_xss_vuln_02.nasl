# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112319");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2017-8763", "CVE-2017-9331", "CVE-2017-9366", "CVE-2017-9621", "CVE-2017-9622", "CVE-2017-9623", "CVE-2017-9624");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-15 18:19:00 +0000 (Mon, 15 May 2017)");
  script_tag(name:"creation_date", value:"2018-06-29 11:16:00 +0200 (Fri, 29 Jun 2018)");
  script_name("EPESI < 1.8.2.1 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_epesi_detect.nasl");
  script_mandatory_keys("epesi/installed");

  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/185");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/186");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/182");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/193");
  script_xref(name:"URL", value:"https://github.com/Telaxus/EPESI/issues/196");

  script_tag(name:"summary", value:"EPESI is prone to multiple cross-site scripting (XSS) vulnerabilities in various parameters.");

  script_tag(name:"affected", value:"EPESI up to and including version 1.8.2.");

  script_tag(name:"solution", value:"Update to EPESI version 1.8.2.1 (rev20170701) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:telaxus:epesi";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);
if(!rev = get_kb_item("epesi/revision")) exit(0);

vers = vers + "-" + rev;

if(version_is_less_equal(version:vers, test_version:"1.8.2-20170701")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.8.2.1 (rev 20170701)");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
