# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icecast:icecast";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15400");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2933");
  script_cve_id("CVE-2001-1083");
  script_xref(name:"OSVDB", value:"5472");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ICECast < 1.3.11 Crafted URL DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_icecast_detect.nasl");
  script_mandatory_keys("icecast/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"ICECast is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"The product is affected by a remote DoS because it does not
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An remote attacker could send specially crafted URL, by adding
  '/', '\' or '.' to the end, that may result in a loss of availability for the service.");

  script_tag(name:"affected", value:"ICECast versions prior to 1.3.11.");

  script_tag(name:"solution", value:"Update to version 1.3.11 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
