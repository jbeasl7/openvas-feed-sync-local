# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0405");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0405)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0405");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0405.html");
  script_xref(name:"URL", value:"http://cgit.freedesktop.org/dbus/dbus/plain/NEWS?h=dbus-1.8");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=89297");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=90021");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=90312");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=90414");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=90952");
  script_xref(name:"URL", value:"https://bugs.freedesktop.org/show_bug.cgi?id=91008");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15937");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the MGASA-2015-0405 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dbus packages provides security hardening and fixes some bugs

Security hardening:

On Unix platforms, change the default configuration for the session bus
to only allow EXTERNAL authentication (secure kernel-mediated
credentials-passing), as was already done for the system bus.

This avoids falling back to DBUS_COOKIE_SHA1, which relies on strongly
unpredictable pseudo-random numbers, under certain circumstances
(/dev/urandom unreadable or malloc() returns NULL), dbus could
fall back to using rand(), which does not have the desired
unpredictability. The fallback to rand() has not been changed in this
stable-branch since the necessary code changes for correct error-handling
are rather intrusive.

If you are using D-Bus over the (unencrypted!) tcp: or nonce-tcp:
transport, in conjunction with DBUS_COOKIE_SHA1 and a shared home
directory using NFS or similar, you will need to reconfigure the session
bus to accept DBUS_COOKIE_SHA1 by commenting out the <auth> element. This
configuration is not recommended.

Other fixes:

Fix a memory leak when GetConnectionCredentials() succeeds
(fd.o #91008, Jacek Bukarewicz)

Ensure that dbus-monitor does not reply to messages intended for others
(fd.o #90952, Simon McVittie)

Add locking to DBusCounter's reference count and notify function
(fd.o #89297, Adrian Szyndela)

Ensure that DBusTransport's reference count is protected by the
corresponding DBusConnection's lock (fd.o #90312, Adrian Szyndela)

Correctly release DBusServer mutex before early-return if we run out
of memory while copying authentication mechanisms (fd.o #90021,
Ralf Habacker)

Correctly initialize all fields of DBusTypeReader (fd.o #90021,
Ralf Habacker, Simon McVittie)

Clean up some memory leaks in test code (fd.o #90021, Ralf Habacker)");

  script_tag(name:"affected", value:"'dbus' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-doc", rpm:"dbus-doc~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus-devel", rpm:"lib64dbus-devel~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dbus1_3", rpm:"lib64dbus1_3~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-devel", rpm:"libdbus-devel~1.8.20~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus1_3", rpm:"libdbus1_3~1.8.20~1.mga5", rls:"MAGEIA5"))) {
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
