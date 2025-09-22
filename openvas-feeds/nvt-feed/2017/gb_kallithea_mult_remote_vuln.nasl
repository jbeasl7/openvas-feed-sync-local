# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kallithea:kallithea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112057");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2016-3691", "CVE-2016-3114");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 16:59:00 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2017-09-27 14:30:52 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.3.2 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Kallithea is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following issues exist:

  - Routes allow GET requests to override the HTTP method which breaks
    the Kallithea CSRF-protection (which only applies to POST requests).

    The attacker might misuse GET requests method overriding to trick users
    into issuing a request with a different method, thus bypassing the
    CSRF protection.

  - A vulnerability that allows logged-in users to edit or
    delete open pull requests associated with any repository to which
    they have read access, plus a related vulnerability allowing logged-in
    users to delete any comments from any repository, provided they could
    determine the comment ID and had read access to just one repository.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users:

  - to edit or delete open pull requests or delete comments by leveraging read access.

  - to bypass the CSRF protection by using the GET HTTP request method.");

  script_tag(name:"affected", value:"Kallithea before version 0.3.2");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.3.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/02/3");

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

if(version_is_less(version:ver, test_version:"0.3.2")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.3.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
