# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:siemens:simatic_s7_1200";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103571");
  script_cve_id("CVE-2012-3037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("2025-04-22T10:32:18+0000");

  script_name("Siemens SIMATIC S7-1200 SSL Private Key Reuse Spoofing Vulnerability (SSA-240718)");

  script_xref(name:"URL", value:"https://cert-portal.siemens.com/productcert/html/ssa-240718.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55559");

  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-09-20 10:18:56 +0200 (Thu, 20 Sep 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-1200 devices are prone to a security
  vulnerability that may allow attackers to spoof SSL certificates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to display incorrect SSL
  certificates. Successful exploits will cause victims to accept the certificates assuming they are
  from a legitimate site.");

  script_tag(name:"affected", value:"Siemens SIMATIC S7-1200 versions 2.x are vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version =~ "^2\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
