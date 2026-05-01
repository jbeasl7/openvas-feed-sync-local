# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:030");
  script_oid("1.3.6.1.4.1.25623.1.0.831575");
  script_version("2026-04-24T15:56:23+0000");
  script_tag(name:"last_modification", value:"2026-04-24 15:56:23 +0000 (Fri, 24 Apr 2026)");
  script_tag(name:"creation_date", value:"2012-08-03 09:50:25 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-1174");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name:"MDVSA", value:"2012:030");
  script_name("Mandriva Update for systemd MDVSA-2012:030 (systemd)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"systemd on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in systemd:

  A TOCTOU race condition was found in the way the systemd-logind
  login manager of the systemd, a system and service manager for Linux,
  performed removal of particular records related with user session upon
  user logout. A local attacker could use this flaw to conduct symbolic
  link attacks, potentially leading to removal of arbitrary system file
  (CVE-2012-1174).

  The updated packages have been patched to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MNDK_2011.0") {
  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~29~8.2", rls:"MNDK_2011.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-gtk", rpm:"systemd-gtk~29~8.2", rls:"MNDK_2011.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~29~8.2", rls:"MNDK_2011.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-units", rpm:"systemd-units~29~8.2", rls:"MNDK_2011.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
