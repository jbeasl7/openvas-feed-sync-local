# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63247");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2006-7234", "CVE-2007-1320", "CVE-2007-5729", "CVE-2008-2382", "CVE-2008-2383", "CVE-2008-3641", "CVE-2008-4690", "CVE-2008-4865", "CVE-2008-5187", "CVE-2008-5286", "CVE-2008-5714");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Summary (SUSE-SR:2009:002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SR:2009:002.  SuSE Security Summaries are short
on detail when it comes to the names of packages affected by
a particular bug. Because of this, while this test will detect
out of date packages, it cannot tell you what bugs impact
which packages, or vice versa.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"boinc-client", rpm:"boinc-client~6.2.18~2.20.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"boinc-client-devel", rpm:"boinc-client-devel~6.2.18~2.20.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"boinc-gui", rpm:"boinc-gui~6.2.18~2.20.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"boinc-gui-lang", rpm:"boinc-gui-lang~6.2.18~2.20.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"conduit", rpm:"conduit~0.3.15~2.27.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kde4-amarok", rpm:"kde4-amarok~2.0.1.1~2.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kde4-amarok-lang", rpm:"kde4-amarok-lang~2.0.1.1~2.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.20~0.1", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
