# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:best_practical_solutions:request_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811528");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-5475", "CVE-2015-6506");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-07-18 16:33:24 +0530 (Tue, 18 Jul 2017)");
  script_name("Request Tracker Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Request Tracker is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of public key parameter in the cryptography
    interface.

  - An insufficient sanitization of vectors related to the (1) user and (2)
    group rights management pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Request Tracker 4.x before 4.2.12.");

  script_tag(name:"solution", value:"Upgrade to Request Tracker version 4.2.12,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://docs.bestpractical.com/release-notes/rt/4.2.12");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76364");
  script_xref(name:"URL", value:"https://bestpractical.com/blog/2015/08/security-vulnerabilities-in-rt");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("rt_detect.nasl");
  script_mandatory_keys("RequestTracker/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^4\.") {
  if(version_is_less(version:version, test_version:"4.2.12")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"4.2.12");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
