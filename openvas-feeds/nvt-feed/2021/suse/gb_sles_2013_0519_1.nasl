# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0519.1");
  script_cve_id("CVE-2013-0213", "CVE-2013-0214");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0519-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130519-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Samba' package(s) announced via the SUSE-SU-2013:0519-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Samba Web Administration Tool (SWAT) in Samba versions 3.0.x to 4.0.1 was affected by a cross-site request forgery, CVE-2013-0214, (bnc#799641).

The Samba Web Administration Tool (SWAT) in Samba versions 3.0.x to 4.0.1 could possibly be used in clickjacking attacks, CVE-2013-0213, (bnc#800982).

Also the following bugs have been fixed:

 * Don't clutter the spec file diff view, (bnc#783384).
 * s3: Fix uninitialized memory read in talloc_free(),
(bnc#764577).
 * Attempt to use samlogon validation level 6,
(bso#7945), (bnc#741623).
 * Add PreReq /etc/init.d/nscd to the winbind package,
(bnc#759731).
 * Recover from ncacn_ip_tcp ACCESS_DENIED/SEC_PKG_ERROR lsa errors, (bso#7944), (bnc#755663).
 * Fix lsa_LookupSids3 and lsa_LookupNames4 arguments.

Security Issue references:

 * CVE-2013-0213
>
 * CVE-2013-0214
>");

  script_tag(name:"affected", value:"'Samba' package(s) on SUSE Linux Enterprise Server 10.");

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

if(release == "SLES10.0") {

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gplv3", rpm:"samba-gplv3~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gplv3-client", rpm:"samba-gplv3-client~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gplv3-doc", rpm:"samba-gplv3-doc~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gplv3-krb-printing", rpm:"samba-gplv3-krb-printing~3.4.3~0.47.3", rls:"SLES10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gplv3-winbind", rpm:"samba-gplv3-winbind~3.4.3~0.47.3", rls:"SLES10.0"))) {
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
