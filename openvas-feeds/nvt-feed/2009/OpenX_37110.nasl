# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openx:openx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100364");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4098");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenX Arbitrary File Upload Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("OpenX_detect.nasl");
  script_mandatory_keys("openx/installed");

  script_tag(name:"solution", value:"Reportedly, the vendor fixed this issue in OpenX 2.8.2. Symantec has
not confirmed this information. Please contact the vendor for details.");

  script_tag(name:"summary", value:"OpenX is prone to a vulnerability that lets attackers upload arbitrary
files because the application fails to adequately validate user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code and execute it in the context of the webserver
process. This may facilitate unauthorized access or privilege escalation, other attacks are also possible.

The issue affects OpenX 2.8.1 and prior.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37110");
  script_xref(name:"URL", value:"http://www.openx.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508050");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
