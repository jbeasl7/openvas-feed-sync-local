# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mutt:mutt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900676");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-1390");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mutt 1.5.19 Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mutt_ssh_login_detect.nasl");
  script_mandatory_keys("mutt/detected");

  script_tag(name:"summary", value:"Mutt is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When Mutt is linked with OpenSSL or GnuTLS it allows connections
  only one TLS certificate in the chain instead of verifying the entire chain.");

  script_tag(name:"impact", value:"Successful exploits allow attackers to spoof SSL certificates of
  trusted servers and redirect a user to a malicious web site.");

  script_tag(name:"affected", value:"Mutt version 1.5.19 only on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the references.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35288");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/06/10/2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504979");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "1.5.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
