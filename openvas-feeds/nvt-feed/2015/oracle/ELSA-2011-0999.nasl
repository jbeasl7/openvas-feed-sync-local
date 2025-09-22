# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122119");
  script_cve_id("CVE-2007-6200");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:24 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0999)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0999");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0999.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the ELSA-2011-0999 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.0.6-4]
- fix #700450 - free parsed hostnames
- fix #575022 - set TZ variable after chroot

[3.0.6-3]
- Add upstream patch to fix CVE-2011-1097 - Incremental file-list
 corruption due to temporary file_extra_cnt increments
 Resolves: #688923

[3.0.6-2]
- Remove BuildRequires dependency on popt-devel, until the package
 is being shipped with RHEL-5 (resolve build issues)

[3.0.6-1]
- Rebase to upstream version 3.0.6
 Resolves: #339971, #471182, #575022, #616093
- Make '-d, --dirs options' behaviour backward-compatible with 2.6.8
 Resolves: #339971 (comment #5)
- Truncate a copied sparse file at the end of transaction (-S, --sparse option)
 Resolves: #530866
- Add -fno-strict-aliasing to CFLAGS
- Remove obsolete rsync-2.6.8-xattr_bug.patch
- Switch license to GPLv3+ (upstream change beginning with 3.0.0)");

  script_tag(name:"affected", value:"'rsync' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.0.6~4.el5", rls:"OracleLinux5"))) {
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
