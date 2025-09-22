# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883078");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3863");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-07-04 02:00:43 +0000 (Thu, 04 Jul 2019)");
  script_name("CentOS Update for libssh2 CESA-2019:1652 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:1652");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-July/023349.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2'
  package(s) announced via the CESA-2019:1652 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libssh2 packages provide a library that implements the SSH2 protocol.

Security Fix(es):

  * libssh2: Integer overflow in transport read resulting in out of bounds
write (CVE-2019-3855)

  * libssh2: Integer overflow in keyboard interactive handling resulting in
out of bounds write (CVE-2019-3856)

  * libssh2: Integer overflow in SSH packet processing channel resulting in
out of bounds write (CVE-2019-3857)

  * libssh2: Integer overflow in user authenticate keyboard interactive
allows out-of-bounds writes (CVE-2019-3863)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'libssh2' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.2~3.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.4.2~3.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-docs", rpm:"libssh2-docs~1.4.2~3.el6_10.1", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
