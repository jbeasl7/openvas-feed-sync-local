# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892672");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4747", "CVE-2012-3981");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-11 11:13:14 +0530 (Tue, 11 Sep 2012)");

  script_name("Bugzilla LDAP Code Injection And Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.6.10/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55349");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=785470");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=785511");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=785522");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
information and bypass security restriction on the affected site.");

  script_tag(name:"affected", value:"Bugzilla 2.x and 3.x to 3.6.11, 3.7.x and 4.0.x to 4.0.7, 4.1.x and 4.2.x
to 4.2.2, and 4.3.x to 4.3.2");

  script_tag(name:"insight", value:"The flaws are due to

  - When the user logs in using LDAP, the username is not escaped when building the uid=$username filter which is
used to query the LDAP directory. This could potentially lead to LDAP injection.

  - Extensions are not protected against directory browsing and users can access the source code of the templates
which may contain sensitive data.");

  script_tag(name:"solution", value:"Upgrade to Bugzilla version 4.0.8, 4.2.3, 4.3.3 or higher.");

  script_tag(name:"summary", value:"Bugzilla is prone to code injection and security bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

disc  = "/extensions/create.pl";

if (!bugPort = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: bugPort))
  exit(0);

if (http_vuln_check(port: bugPort, url :dir + disc, check_header: TRUE, pattern:"^\#!\/usr\/bin\/perl -w",
                    extra_check:["^use Bugzilla\;$", "my \$base_dir = bz_locations\(\)->\{'extensionsdir'\}\;"])) {
  security_message(port: bugPort);
  exit(0);
}

exit(99);
