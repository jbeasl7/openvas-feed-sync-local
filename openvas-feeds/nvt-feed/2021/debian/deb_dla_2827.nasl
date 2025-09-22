# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892827");
  script_cve_id("CVE-2019-8921", "CVE-2019-8922", "CVE-2021-41229");
  script_tag(name:"creation_date", value:"2021-11-28 02:00:13 +0000 (Sun, 28 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 18:57:08 +0000 (Tue, 30 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2827-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2827-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bluez");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bluez' package(s) announced via the DLA-2827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BlueZ, the Linux Bluetooth protocol stack. An attacker could cause a denial-of-service (DoS) or leak information.

CVE-2019-8921

SDP infoleak, the vulnerability lies in the handling of a SVC_ATTR_REQ by the SDP implementation of BlueZ. By crafting a malicious CSTATE, it is possible to trick the server into returning more bytes than the buffer actually holds, resulting in leaking arbitrary heap data.

CVE-2019-8922

SDP Heap Overflow, this vulnerability lies in the SDP protocol handling of attribute requests as well. By requesting a huge number of attributes at the same time, an attacker can overflow the static buffer provided to hold the response.

CVE-2021-41229

sdp_cstate_alloc_buf allocates memory which will always be hung in the singly linked list of cstates and will not be freed. This will cause a memory leak over time. The data can be a very large object, which can be caused by an attacker continuously sending sdp packets and this may cause the service of the target device to crash.

For Debian 9 stretch, these problems have been fixed in version 5.43-2+deb9u5.

We recommend that you upgrade your bluez packages.

For the detailed security status of bluez please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'bluez' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-dbg", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3-dbg", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
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
