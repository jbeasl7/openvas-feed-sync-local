# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.72");
  script_cve_id("CVE-2014-3634", "CVE-2014-3683");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-72-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-72-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-72-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rsyslog' package(s) announced via the DLA-72-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Wheezy patch left an unresolved symbol in the imklog module of the Squeeze version. rsyslog worked fine except that messages from the kernel couldn't be submitted any longer. This update fixes this issue.

For reference, the original advisory text follows.

CVE-2014-3634

Fix remote syslog vulnerability due to improper handling of invalid PRI values.

CVE-2014-3683

Followup fix for CVE-2014-3634. The initial patch was incomplete. It did not cover cases where PRI values > MAX_INT caused integer overflows resulting in negative values.

For Debian 6 Squeeze, these issues have been fixed in rsyslog version 4.6.4-2+deb6u2");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-doc", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-relp", ver:"4.6.4-2+deb6u1", rls:"DEB6"))) {
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
