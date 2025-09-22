# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170205");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2022-11-02 15:31:38 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2022-3788");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress TablePress Plugin <= 1.14 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"The WordPress plugin 'TablePress' is prone to a cross-site
  scripting (XSS) vulnerability.

  This VT has been deprecated since further investigation showed that it was not a security
  issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Affected is an unknown function of the component Table Import
  Handler. The manipulation of the argument Import data leads to cross site scripting. It is
  possible to launch the attack remotely.");

  script_tag(name:"affected", value:"WordPress TablePress plugin version 1.14 and prior.");

  script_tag(name:"solution", value:"No solution is required.

  Note: Further investigation showed that it was not a security issue.");

  script_xref(name:"URL", value:"https://wordpress.org/support/topic/wordfence-issuing-security-warning");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
