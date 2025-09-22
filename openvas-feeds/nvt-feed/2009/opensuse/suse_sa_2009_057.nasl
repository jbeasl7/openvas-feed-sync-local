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
  script_oid("1.3.6.1.4.1.25623.1.0.66302");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
  script_cve_id("CVE-2009-3555");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("SUSE: Security Advisory for openssl (SUSE-SA:2009:057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.2|openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"insight", value:"The TLS/SSLv3 protocol as implemented in openssl prior to this update
was not able to associate already sent data to a renegotiated connection.
This allowed man-in-the-middle attackers to inject HTTP requests in a
HTTPS session without being noticed.
For example Apache's mod_ssl was vulnerable to this kind of attack because
it uses openssl.

It is believed that this vulnerability is actively exploited in the wild to
get access to HTTPS protected web-sites.

Please note that renegotiation will be disabled for any application using
openssl by this update and may cause problems in some cases.
Additionally this attack is not limited to HTTP.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:057");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:057.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~149.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~149.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~149.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo", rpm:"compat-openssl097g-debuginfo~0.9.7g~119.7", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debugsource", rpm:"compat-openssl097g-debugsource~0.9.7g~119.7", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~119.7", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8h~28.2.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~0.9.8h~25.2.13", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-64bit", rpm:"compat-openssl097g-debuginfo-64bit~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-64bit", rpm:"compat-openssl097g-64bit~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-64bit", rpm:"libopenssl0_9_8-64bit~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-64bit", rpm:"compat-openssl097g-64bit~0.9.7g~119.7", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-64bit", rpm:"libopenssl0_9_8-64bit~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-32bit", rpm:"compat-openssl097g-debuginfo-32bit~0.9.7g~149.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~149.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8k~3.5.3", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-debuginfo-32bit", rpm:"compat-openssl097g-debuginfo-32bit~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~146.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8h~28.11.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~119.7", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8g~47.10", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
