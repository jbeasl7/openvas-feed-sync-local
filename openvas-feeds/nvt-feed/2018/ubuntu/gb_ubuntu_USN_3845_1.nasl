# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843855");
  script_cve_id("CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_tag(name:"creation_date", value:"2018-12-13 06:30:11 +0000 (Thu, 13 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 18:05:55 +0000 (Fri, 28 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3845-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3845-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3845-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp, freerdp2' package(s) announced via the USN-3845-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8784, CVE-2018-8785)

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps. A malicious server
could use this issue to cause FreeRDP to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2018-8786, CVE-2018-8787)

Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8788)

Eyal Itkin discovered FreeRDP incorrectly handled NTLM authentication. A
malicious server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8789)");

  script_tag(name:"affected", value:"'freerdp, freerdp2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp1", ver:"1.0.2-2ubuntu1.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1", rls:"UBUNTU18.10"))) {
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
