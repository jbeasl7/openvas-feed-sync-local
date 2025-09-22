# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kallithea:kallithea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112058");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-1864");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 16:59:00 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2017-09-27 15:00:33 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.2.1 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"Kallithea is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HTML and Javascript injection was possible in several places in the Kallithea UI,
    allowing attackers to run malicious code.

    User details (first name, last name) as well as repository, repository group and user group descriptions were pasted
    unfiltered into the HTML code, thus attacker could inject malicious code.");

  script_tag(name:"impact", value:"As the vulnerability allows attacker to execute arbitrary code in the
    user's browser, it can be used to gain access to the user's account by
    stealing credentials, like API keys. It is also possible for the attacker to gain full
    administrator access to the Kallithea instance.");

  script_tag(name:"affected", value:"Kallithea before version 0.2.1");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/14/12");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74184");
  script_xref(name:"URL", value:"https://kallithea-scm.org/security/cve-2015-1864.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kallithea_detect.nasl");
  script_mandatory_keys("Kallithea/Installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:ver, test_version:"0.2.1")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.2.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
