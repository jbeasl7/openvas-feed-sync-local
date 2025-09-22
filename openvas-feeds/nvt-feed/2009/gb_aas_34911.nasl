# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:klinzmann:application_access_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100197");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_cve_id("CVE-2009-1464", "CVE-2009-1465", "CVE-2009-1466");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 15:20:00 +0000 (Wed, 14 Feb 2024)");

  script_name("A-A-S Application Access Server <= 2.0.48 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_aas_http_detect.nasl");
  script_mandatory_keys("aas/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34911");

  script_tag(name:"summary", value:"A-A-S Application Access Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - cross-site request-forgery (CSRF) vulnerability

  - insecure default password vulnerability

  - information disclosure vulnerability");

  script_tag(name:"impact", value:"Attackers can exploit these issues to run privileged commands on
  the affected computer and gain unauthorized administrative access to the affected application and
  the underlying system.");

  script_tag(name:"affected", value:"These issues affect version 2.0.48. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.0.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
