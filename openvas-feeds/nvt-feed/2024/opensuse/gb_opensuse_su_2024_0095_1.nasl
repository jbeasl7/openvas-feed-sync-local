# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856041");
  script_version("2025-02-26T05:38:40+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-31 01:06:25 +0000 (Sun, 31 Mar 2024)");
  script_name("openSUSE: Security Advisory for kanidm (openSUSE-SU-2024:0095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0095-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NKJULBOBLCBFHPQE3UTQ6SUJ5LZ43XC7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kanidm'
  package(s) announced via the openSUSE-SU-2024:0095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kanidm fixes the following issues:

     Update to version 1.1.0~rc16~git6.e51d0de:

  * [SECURITY: LOW] Administrator triggered thread crash in oauth2 claim
       maps #2686 (#2686)

  * return consent map to service account (#2604)");

  script_tag(name:"affected", value:"'kanidm' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kanidm-1.1.0-rc16", rpm:"kanidm-1.1.0-rc16~git6.e51d0de~bp155.14.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanidm-clients-1.1.0-rc16", rpm:"kanidm-clients-1.1.0-rc16~git6.e51d0de~bp155.14.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanidm-docs-1.1.0-rc16", rpm:"kanidm-docs-1.1.0-rc16~git6.e51d0de~bp155.14.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanidm-server-1.1.0-rc16", rpm:"kanidm-server-1.1.0-rc16~git6.e51d0de~bp155.14.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kanidm-unixd-clients-1.1.0-rc16", rpm:"kanidm-unixd-clients-1.1.0-rc16~git6.e51d0de~bp155.14.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
