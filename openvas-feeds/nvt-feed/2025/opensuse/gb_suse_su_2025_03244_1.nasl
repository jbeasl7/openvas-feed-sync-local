# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03244.1");
  script_cve_id("CVE-2024-57822", "CVE-2024-57823");
  script_tag(name:"creation_date", value:"2025-09-19 04:06:37 +0000 (Fri, 19 Sep 2025)");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03244-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03244-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503244-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235674");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor' package(s) announced via the SUSE-SU-2025:03244-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for raptor fixes the following issues:

- CVE-2024-57823: Fixed integer underflow when normalizing a URI with the turtle parser (bsc#1235673)
- CVE-2024-57822: Fixed heap buffer overread when parsing triples with the nquads parser (bsc#1235674)");

  script_tag(name:"affected", value:"'raptor' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libraptor-devel", rpm:"libraptor-devel~2.0.15~150200.9.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0", rpm:"libraptor2-0~2.0.15~150200.9.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-0-32bit", rpm:"libraptor2-0-32bit~2.0.15~150200.9.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor", rpm:"raptor~2.0.15~150200.9.18.1", rls:"openSUSELeap15.6"))) {
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
