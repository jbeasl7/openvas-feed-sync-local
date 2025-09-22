# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103613");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-12-03 10:22:01 +0100 (Mon, 03 Dec 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-0308");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway < 10.0 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Symantec Messaging Gateway is prone to a cross-site request
  forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue may allow a remote attacker to perform
  certain unauthorized actions and gain access to the affected application. Other attacks are also
  possible.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway versions prior to 10.0.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the reference for
  more details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55137");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
