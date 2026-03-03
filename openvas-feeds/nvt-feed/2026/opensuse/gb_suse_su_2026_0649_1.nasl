# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0649.1");
  script_cve_id("CVE-2026-24491", "CVE-2026-24675", "CVE-2026-24676", "CVE-2026-24679", "CVE-2026-24681", "CVE-2026-24682", "CVE-2026-24683", "CVE-2026-24684");
  script_tag(name:"creation_date", value:"2026-03-02 04:36:59 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 15:08:26 +0000 (Tue, 10 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0649-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0649-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260649-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257991");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2026:0649-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2026-24491: heap-use-after-free in video_timer (bsc#1257981).
- CVE-2026-24675: heap-use-after-free in urb_select_interface (bsc#1257982).
- CVE-2026-24676: heap-use-after-free in audio_format_compatible (bsc#1257983).
- CVE-2026-24679: heap-buffer-overflow in urb_select_interface (bsc#1257986).
- CVE-2026-24681: heap-use-after-free in urb_bulk_transfer_cb (bsc#1257988).
- CVE-2026-24682: heap-buffer-overflow in audio_formats_free (bsc#1257989).
- CVE-2026-24683: heap-use-after-free in ainput_send_input_event (bsc#1257990).
- CVE-2026-24684: heap-use-after-free in play_thread (bsc#1257991).");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-2", rpm:"libfreerdp2-2~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-2", rpm:"libwinpr2-2~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr-devel", rpm:"winpr-devel~2.11.2~150600.4.9.1", rls:"openSUSELeap15.6"))) {
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
