# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803973");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-05 13:26:26 +0530 (Thu, 05 Dec 2013)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2013-4055", "CVE-2013-4051", "CVE-2013-4050");

  script_name("IBM Lotus Domino Web Administrator Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"IBM Lotus Domino is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaw is in the webadmin.nsf file in Domino Web Administrator which fails
  to validate user supplied input properly.");

  script_tag(name:"affected", value:"IBM Lotus Domino 8.5 and 9.0.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to hijack
  the authentication of unspecified victims.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63578");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21652988");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if(version_is_equal(version:version, test_version:"8.5.0") ||
   version_is_equal(version:version, test_version:"9.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
