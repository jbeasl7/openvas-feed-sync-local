# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:best_practical_solutions:request_tracker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804718");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2014-1474");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-24 15:22:19 +0530 (Thu, 24 Jul 2014)");
  script_name("Request Tracker (RT) 'Email::Address::List' Remote Denial of Service Vulnerability");

  script_tag(name:"summary", value:"Request Tracker (RT) is prone to remote denial of service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An algorithmic complexity flaw is in Perl CPAN Email::Address::List that is
triggered when handling a specially crafted string without an address.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to consume CPU resource resulting
in denial of service.");
  script_tag(name:"affected", value:"Request Tracker (RT) version 4.2.0 through 4.2.2");
  script_tag(name:"solution", value:"Upgrade to version 4.2.5 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://blog.bestpractical.com/2014/01/security-vulnerability-in-rt-42.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68690");
  script_xref(name:"URL", value:"http://lists.bestpractical.com/pipermail/rt-announce/2014-June/000257.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
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

if(version_in_range(version:version, test_version:"4.2.0", test_version2:"4.2.2")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.2.0 - 4.2.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
