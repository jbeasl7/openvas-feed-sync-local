# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704647");
  script_cve_id("CVE-2020-0556");
  script_tag(name:"creation_date", value:"2020-03-29 03:00:16 +0000 (Sun, 29 Mar 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-17 17:56:49 +0000 (Tue, 17 Mar 2020)");

  script_name("Debian: Security Advisory (DSA-4647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4647-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4647-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4647");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bluez");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bluez' package(s) announced via the DSA-4647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that the BlueZ's HID and HOGP profile implementations don't specifically require bonding between the device and the host. Malicious devices can take advantage of this flaw to connect to a target host and impersonate an existing HID device without security or to cause an SDP or GATT service discovery to take place which would allow HID reports to be injected to the input subsystem from a non-bonded source.

For the HID profile an new configuration option (ClassicBondedOnly) is introduced to make sure that input connections only come from bonded device connections. The options defaults to false to maximize device compatibility.

For the oldstable distribution (stretch), this problem has been fixed in version 5.43-2+deb9u2.

For the stable distribution (buster), this problem has been fixed in version 5.50-1.2~deb10u1.

We recommend that you upgrade your bluez packages.

For the detailed security status of bluez please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bluez' package(s) on Debian 9, Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.50-1.2~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-dbg", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3-dbg", ver:"5.43-2+deb9u2", rls:"DEB9"))) {
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
