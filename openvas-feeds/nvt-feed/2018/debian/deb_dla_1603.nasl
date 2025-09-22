# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891603");
  script_cve_id("CVE-2017-15377", "CVE-2017-7177", "CVE-2018-6794");
  script_tag(name:"creation_date", value:"2018-12-04 23:00:00 +0000 (Tue, 04 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-13 16:35:04 +0000 (Tue, 13 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-1603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1603-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1603-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'suricata' package(s) announced via the DLA-1603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were found in suricata, an intrusion detection and prevention tool.

CVE-2017-7177

Suricata has an IPv4 defragmentation evasion issue caused by lack of a check for the IP protocol during fragment matching.

CVE-2017-15377

It was possible to trigger lots of redundant checks on the content of crafted network traffic with a certain signature, because of DetectEngineContentInspection in detect-engine-content-inspection.c. The search engine doesn't stop when it should after no match is found, instead, it stops only upon reaching inspection-recursion limit (3000 by default).

CVE-2018-6794

Suricata is prone to an HTTP detection bypass vulnerability in detect.c and stream-tcp.c. If a malicious server breaks a normal TCP flow and sends data before the 3-way handshake is complete, then the data sent by the malicious server will be accepted by web clients such as a web browser or Linux CLI utilities, but ignored by Suricata IDS signatures. This mostly affects IDS signatures for the HTTP protocol and TCP stream content, signatures for TCP packets will inspect such network traffic as usual.

TEMP-0856648-2BC2C9 (no CVE assigned yet)

Out of bounds read in app-layer-dns-common.c. On a zero size A or AAAA record, 4 or 16 bytes would still be read.

For Debian 8 Jessie, these problems have been fixed in version 2.0.7-2+deb8u3.

We recommend that you upgrade your suricata packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'suricata' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"suricata", ver:"2.0.7-2+deb8u3", rls:"DEB8"))) {
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
