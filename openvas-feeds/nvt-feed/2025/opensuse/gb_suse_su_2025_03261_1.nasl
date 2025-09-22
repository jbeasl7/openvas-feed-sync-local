# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03261.1");
  script_cve_id("CVE-2024-47175", "CVE-2025-58060", "CVE-2025-58364");
  script_tag(name:"creation_date", value:"2025-09-19 04:06:37 +0000 (Fri, 19 Sep 2025)");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03261-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03261-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503261-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249128");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041765.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2025:03261-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

- CVE-2024-47175: no validation of IPP attributes in `ppdCreatePPDFromIPP2` when writing to a temporary PPD file allows
 for the injection of attacker-controlled data to the resulting PPD (bsc#1230932).
- CVE-2025-58060: no password check when `AuthType` is set to anything but `Basic` and a request is made with an
 `Authorization: Basic` header (bsc#1249049).
- CVE-2025-58364: unsafe deserialization and validation of printer attributes leads to NULL pointer dereference
 (bsc#1249128).");

  script_tag(name:"affected", value:"'cups' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.72.1", rls:"openSUSELeap15.6"))) {
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
