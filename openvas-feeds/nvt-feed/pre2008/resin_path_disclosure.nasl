# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:caucho:resin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11048");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2002-2090");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Caucho Resin <= 2.1.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("gb_caucho_resin_http_detect.nasl");
  script_mandatory_keys("caucho/resin/detected");

  script_tag(name:"summary", value:"Caucho Resin will reveal the physical path of the webroot
  when asked for a special DOS device, e.g. lpt9.xtp.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain further knowledge
  about the remote filesystem layout.");

  script_tag(name:"affected", value:"Caucho Resin version 2.1.2 and prior.");

  script_tag(name:"solution", value:"Update to a later software version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5252");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
