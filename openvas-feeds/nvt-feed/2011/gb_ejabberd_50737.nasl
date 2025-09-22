# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:process-one:ejabberd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103369");
  script_cve_id("CVE-2011-4320");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("ejabberd 'mod_pubsub' Module Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50737");
  script_xref(name:"URL", value:"http://www.process-one.net/en/ejabberd/release_notes/release_note_ejabberd_2.1.9/");
  script_xref(name:"URL", value:"https://support.process-one.net/browse/EJAB-1498");

  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-20 11:14:21 +0100 (Tue, 20 Dec 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_ejabberd_consolidation.nasl");
  script_mandatory_keys("ejabberd/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"ejabberd is prone to a vulnerability that may allow attackers to cause
  an affected application to enter an infinite loop, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"ejabberd prior to version 2.1.9.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
