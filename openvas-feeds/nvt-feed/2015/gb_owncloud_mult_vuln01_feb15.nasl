# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805279");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-9047", "CVE-2014-9048", "CVE-2014-9049");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-02-19 15:04:16 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud Multiple Vulnerabilities -01 (Feb 2015)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist due to:

  - Multiple unspecified flaws related to the 'enable_previews' switch in the
  config.php script.

  - Two flaws in the Documents application that is due to the persistence of an
  unspecified legacy API method and missing access controls in the API.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to gain access to arbitrary local files, gain access to
  session ID information and recently edited documents of every existing user
  and bypass the password-protection gaining access to shared files.");

  script_tag(name:"affected", value:"ownCloud Server 6.x before 6.0.6 and
  7.x before 7.0.3");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 6.0.6 or 7.0.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71378");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-025");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-026");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^[67]") {

  if(version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.5")) {
    fix = "6.0.6";
    VULN = TRUE;
  }

  if(version_in_range(version:version, test_version:"7.0.0", test_version2:"7.0.2")) {
    fix = "7.0.3";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
