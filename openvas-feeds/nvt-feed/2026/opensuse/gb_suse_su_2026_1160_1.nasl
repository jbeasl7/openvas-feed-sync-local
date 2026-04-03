# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1160.1");
  script_cve_id("CVE-2026-26271", "CVE-2026-26955", "CVE-2026-26965", "CVE-2026-31806", "CVE-2026-31883", "CVE-2026-31885");
  script_tag(name:"creation_date", value:"2026-04-01 08:03:29 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-02T06:06:11+0000");
  script_tag(name:"last_modification", value:"2026-04-02 06:06:11 +0000 (Thu, 02 Apr 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 14:26:13 +0000 (Tue, 17 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1160-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261160-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259686");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-March/045202.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2026:1160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2026-26271: Buffer Overread in FreeRDP Icon Processing (bsc#1258979).
- CVE-2026-26955: Out-of-bounds Write in freerdp (bsc#1258982).
- CVE-2026-26965: Out-of-bounds Write in freerdp (bsc#1258985).
- CVE-2026-31806: improper validation of server messages can lead to a heap buffer overflow and arbitrary code execution
 (bsc#1259653).
- CVE-2026-31883: crafted RDPSND audio format and wave data can cause a heap buffer overflow write (bsc#1259679).
- CVE-2026-31885: unchecked predictor can lead to an out-of-bounds read (bsc#1259686).");

  script_tag(name:"affected", value:"'freerdp' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-2", rpm:"libfreerdp2-2~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-2", rpm:"libwinpr2-2~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr-devel", rpm:"winpr-devel~2.11.2~150600.4.18.1", rls:"openSUSELeap15.6"))) {
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
