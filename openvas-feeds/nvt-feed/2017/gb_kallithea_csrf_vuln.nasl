# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kallithea:kallithea";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112059");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-0276");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 16:58:00 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2017-09-27 15:07:24 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Kallithea < 0.2 CSRF Vulnerability");

  script_tag(name:"summary", value:"A vulnerability has been found in Kallithea,
  allowing attackers to gain unauthorised access to the account of a logged in user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Pages that present forms to the user and accept user input don't provide synchronisation tokens to prevent cross-site request forgery.

    It is possible to change an email address of a user by tricking them into clicking a link that initiates a malicious HTTP request.

    After this, the attacker can request a password reset, the link is then sent to their new email address.
    Then the attacker changes the email address back to the original, and doesn't log out, saving the cookie.

    At this point, the attacker has full access to the user's account. The user can't login (the password has changed),
    but might think that he forgot the password, has an account lockout, or an expired account. The user does a password reset, but the attacker still has the access.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to steal the account of an active user by using social engineering techniques.
    In the case the user also has administrator rights, it is possible for the attacker to gain full administrator access to the Kallithea instance.");

  script_tag(name:"affected", value:"Kallithea before version 0.2");

  script_tag(name:"solution", value:"Upgrade to Kallithea version 0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/04/10/8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74052");
  script_xref(name:"URL", value:"https://kallithea-scm.org/security/cve-2015-0276.html");

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

if(version_is_less(version:ver, test_version:"0.2")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"0.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
