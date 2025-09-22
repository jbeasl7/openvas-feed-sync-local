# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833723");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:18:09 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for fdo (SUSE-SU-2023:4549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4549-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RU7PRGUFWDQNP2WLBOPXCZR5DPVKCRU3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fdo'
  package(s) announced via the SUSE-SU-2023:4549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fdo-client fixes the following issues:

  * Removed build key via utils/keys_gen.sh. (bsc#1216293)");

  script_tag(name:"affected", value:"'fdo' package(s) on openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-devel", rpm:"fdo-client-devel~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client", rpm:"fdo-client~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debuginfo", rpm:"fdo-client-debuginfo~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debugsource", rpm:"fdo-client-debugsource~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-devel", rpm:"fdo-client-devel~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client", rpm:"fdo-client~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debuginfo", rpm:"fdo-client-debuginfo~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debugsource", rpm:"fdo-client-debugsource~1.0.0+git20210816.baa09b5~150400.3.3.1", rls:"openSUSELeapMicro5.4"))) {
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
