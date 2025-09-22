# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148464");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-07-15 03:57:09 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-25 23:48:00 +0000 (Mon, 25 Jul 2022)");

  script_cve_id("CVE-2022-30550");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Dovecot 2.2.x <= 2.3.20 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When two passdb configuration entries exist in Dovecot
  configuration, which have the same driver and args settings, the incorrect username_filter and
  mechanism settings can be applied to passdb definitions. These incorrectly applied settings can
  lead to an unintended security configuration and can permit privilege escalation with certain
  configurations involving master user authentication.

  Dovecot documentation does not advise against the use of passdb definitions which have the same
  driver and args settings. One such configuration would be where an administrator wishes to use
  the same pam configuration or passwd file for both normal and master users but use the
  username_filter setting to restrict which of the users is able to be a master user.");

  script_tag(name:"impact", value:"If same passwd file or PAM is used for both normal and master
  users, it is possible for an attacker to become master user.");

  script_tag(name:"affected", value:"Dovecot version 2.2.x through 2.3.20.");

  # nb: Only "Fixed in main" with the commit below. Check on https://github.com/dovecot/core/tags
  # if a version later then 2.3.19.1 was released containing the commit below.
  # The vendor mentioned, that a fix will be released in 2.4.x. See last link below.
  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2022-July/000478.html");
  script_xref(name:"URL", value:"https://github.com/dovecot/core/commit/7bad6a24160e34bce8f10e73dbbf9e5fbbcd1904");
  script_xref(name:"URL", value:"https://dovecot.org/mailman3/archives/list/dovecot@dovecot.org/message/T7YVZ35FVDXW7VM7F32P52KEP5F5IO3F");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2", test_version2: "2.3.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
