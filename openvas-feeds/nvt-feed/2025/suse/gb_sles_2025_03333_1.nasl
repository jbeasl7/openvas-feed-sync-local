# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03333.1");
  script_cve_id("CVE-2024-52615");
  script_tag(name:"creation_date", value:"2025-09-25 04:12:26 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-21 21:15:23 +0000 (Thu, 21 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503333-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233421");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041824.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi' package(s) announced via the SUSE-SU-2025:03333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for avahi fixes the following issues:

- CVE-2024-52615: wide-area DNS uses constant source port for queries and can expose the Avahi-daemon to DNS spoofing
 attacks (bsc#1233421).");

  script_tag(name:"affected", value:"'avahi' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-compat-mDNSResponder-devel", rpm:"avahi-compat-mDNSResponder-devel~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-lang", rpm:"avahi-lang~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"avahi-utils", rpm:"avahi-utils~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3", rpm:"libavahi-client3~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-client3-32bit", rpm:"libavahi-client3-32bit~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3", rpm:"libavahi-common3~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-common3-32bit", rpm:"libavahi-common3-32bit~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-core7", rpm:"libavahi-core7~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-devel", rpm:"libavahi-devel~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib-devel", rpm:"libavahi-glib-devel~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-glib1", rpm:"libavahi-glib1~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-gobject0", rpm:"libavahi-gobject0~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-libevent1", rpm:"libavahi-libevent1~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavahi-ui-gtk3-0", rpm:"libavahi-ui-gtk3-0~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns_sd", rpm:"libdns_sd~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhowl0", rpm:"libhowl0~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Avahi-0_6", rpm:"typelib-1_0-Avahi-0_6~0.8~150600.15.9.1", rls:"SLES15.0SP6"))) {
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
