# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:tp-link:mr3220_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811881");
  script_version("2025-04-08T05:43:28+0000");
  script_tag(name:"last_modification", value:"2025-04-08 05:43:28 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-25 15:11:30 +0530 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 20:20:00 +0000 (Tue, 07 Nov 2017)");

  script_cve_id("CVE-2017-15291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TP-Link TL-MR3220 XSS Vulnerability (CVE-2017-15291)");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tp_link_routers_http_detect.nasl");
  script_mandatory_keys("tp-link/router/detected");

  script_tag(name:"summary", value:"TP-Link TL-MR3220 Wireless N Router devices are prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable model.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient validation of user
  supplied input via Description field in Wireless MAC Filtering page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and launch other
  attacks.");

  script_tag(name:"affected", value:"TP-Link TL-MR3220 devices in all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://fireshellsecurity.team/assets/pdf/Router-TP-LINK-TL-MR3220-Vulnerability-XSS.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43023");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

report = report_fixed_ver(installed_version:"unknown", fixed_version:"None");
security_message(port:port, data:report);
exit(0);