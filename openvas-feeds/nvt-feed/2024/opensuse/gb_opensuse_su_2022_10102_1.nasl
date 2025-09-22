# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833397");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-6083");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:52:14 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for freeciv (openSUSE-SU-2022:10102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10102-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CCKMMZKZ7XX4APE5H2QGYEIBBFEJYFIN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeciv'
  package(s) announced via the openSUSE-SU-2022:10102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freeciv fixes the following issues:

  - update to 3.0.3 (boo#1202548, CVE-2022-6083):

  * 3.0.3 is a bugfix release

  - update to 3.0.2:

  * 3.0.2 is a generic bugfix release

  - update to 3.0.1:

  * 3.0.1 is a generic bugfix release

  - update to 3.0.0:

  * This release is a major upgrade which with some changes that can
         support backward compatible rulesets

  * see

  - update to 2.6.6:

  * 2.6.6 is a bugfix release.");

  script_tag(name:"affected", value:"'freeciv' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"freeciv", rpm:"freeciv~3.0.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-gtk3", rpm:"freeciv-gtk3~3.0.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-lang", rpm:"freeciv-lang~3.0.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeciv-qt", rpm:"freeciv-qt~3.0.3~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
