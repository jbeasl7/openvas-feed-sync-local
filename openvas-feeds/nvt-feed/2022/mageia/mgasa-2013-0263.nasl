# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0263");
  script_cve_id("CVE-2013-2219", "CVE-2013-4283");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0263");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0263.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10138");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10889");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1119.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1182.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the MGASA-2013-0263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated 389-ds-base packages fix security vulnerabilities:

It was discovered that the 389 Directory Server did not honor defined
attribute access controls when evaluating search filter expressions. A
remote attacker (with permission to query the Directory Server) could use
this flaw to determine the values of restricted attributes via a series of
search queries with filter conditions that used restricted attributes
(CVE-2013-2219).

It was discovered that the 389 Directory Server did not properly handle the
receipt of certain MOD operations with a bogus Distinguished Name (DN). A
remote, unauthenticated attacker could use this flaw to cause the 389
Directory Server to crash (CVE-2013-4283).

Additionally, problems of wrong default group nobody (from upstream) as well
as the 389-ds server not starting after a reboot have been fixed (mga#10138).");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Mageia 3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.0.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.0.8~1.mga3", rls:"MAGEIA3"))) {
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
