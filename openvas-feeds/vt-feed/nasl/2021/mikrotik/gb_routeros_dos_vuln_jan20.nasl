# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146341");
  script_version("2026-09-16T05:46:31+0000");
  script_tag(name:"last_modification", value:"2026-09-16 05:46:31 +0000 (Wed, 16 Sep 2026)");
  # nb: This was initially a single VT which got split later into two due to different affected /
  # fixed versions. As both CVEs got covered back then in 2021 the original creation date has been
  # kept.
  script_tag(name:"creation_date", value:"2021-07-21 06:35:18 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-08 13:26:49 +0000 (Thu, 08 Jul 2021)");

  script_cve_id("CVE-2020-20211");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.44.6, 6.45.x <= 6.46.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS suffers from an assertion failure
  vulnerability in the /nova/bin/console process.");

  script_tag(name:"impact", value:"An authenticated remote attacker can cause a DoS due to an
  assertion failure via a crafted packet.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions prior to 6.44.6 and 6.45.x up to at
  least version 6.46.5.");

  script_tag(name:"solution", value:"- Update to version 6.44.6 for the affected long-term release
  tree

  - No fixed version is known for the affected stable release tree

  Please contact the vendor for more information.");

  # nb: Original disclosure of two independent flaws in the console process:
  #
  # - memory corruption (the other one handled in a separate VT) tracked as "1st issue" by the
  #   security researcher and later assigned CVE-2020-20212
  # - assertion failure (this one) tracked as "2nd issue" by the security researcher and later
  #   assigned CVE-2020-20211
  #
  # which both initially got tracked as being fixed in this version:
  #
  # > Affected Versions: before 6.44.6 (Long-term release tree)
  # > Fixed Versions: 6.44.6 (Long-term release tree)
  #
  # but one of both turned out to be actually not fixed (see next comment).
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/Jan/12");

  # nb: Next mentions the following:
  #
  # > The latest stable release tree 6.46.5 still suffers from these two vulnerabilities.
  #
  # and at the disclosure timeline at the bottom this:
  #
  # > 2019/12/02 notified the vendor the 1st issue still exists in version 6.44.6 (2nd issue fixed)
  #
  # which basically means:
  #
  # - CVE-2020-20211 (handled here): < 6.44.6 and 6.45.x <= 6.46.5 affected (6.44.6 is the only
  #   known fix)
  #
  # - CVE-2020-20212 (handled in the other VT): <= 6.44.6 and 6.45.x <= 6.46.5 affected (no fix
  #   known so far)
  #
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/Apr/7");

  # nb: The earlier mentioned CVE assignment for both flaws.
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/May/0");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs?channelFilter=&versionFilter=6.44.6");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/v6-44-6-long-term-is-released/134263/1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.44.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.45.0", test_version2: "6.46.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Unknown");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: No exit(99) as later versions might have been affected as well and the fix is unknown.
exit(0);
