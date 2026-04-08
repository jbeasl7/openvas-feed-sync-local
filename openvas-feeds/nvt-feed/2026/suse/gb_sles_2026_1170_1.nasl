# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1170.1");
  script_cve_id("CVE-2026-2474");
  script_tag(name:"creation_date", value:"2026-04-06 04:58:43 +0000 (Mon, 06 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1170-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261170-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258266");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045263.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Crypt-URandom' package(s) announced via the SUSE-SU-2026:1170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-Crypt-URandom fixes the following issue:

Update to 0.550.0 (0.55):

- CVE-2026-2474: heap buffer overflow in the XS function `crypt_urandom_getrandom()` (bsc#1258266).

Changelog:

- Fix for sysread/read failures. Thanks to Miha Purg for GH#20.
- Fix for test suite failures on STDOUT encoding. Thanks to Lukas Mai for GH#19.

For full changelog see /usr/share/doc/packages/perl-Crypt-URandom/Changes.");

  script_tag(name:"affected", value:"'perl-Crypt-URandom' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Crypt-URandom", rpm:"perl-Crypt-URandom~0.550.0~1.6.1", rls:"SLES12.0SP5"))) {
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
