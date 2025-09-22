# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:siemens:ruggedcom_rugged_operating_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103635");
  script_cve_id("CVE-2012-4698");
  script_version("2023-07-27T05:05:08+0000");
  script_name("Rugged Operating System Private Key Disclosure Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-04 13:15:52 +0100 (Fri, 04 Jan 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_siemens_ruggedcom_consolidation.nasl");
  script_mandatory_keys("siemens_ruggedcom/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55123");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Rugged Operating System is prone to an information-disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain the SSL certificate's
  private key and use it to decrypt SSL traffic between an end user and a RuggedCom network device.");

  script_tag(name:"affected", value:"Rugged Operating System 3.11.0 and previous versions are affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:vers, test_version:"3.11.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.11.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
