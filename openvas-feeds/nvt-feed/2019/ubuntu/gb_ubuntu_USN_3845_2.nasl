# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844025");
  script_cve_id("CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_tag(name:"creation_date", value:"2019-05-29 02:00:29 +0000 (Wed, 29 May 2019)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 18:05:55 +0000 (Fri, 28 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3845-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3845-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3845-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the USN-3845-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3845-1 fixed several vulnerabilities in FreeRDP. This update provides the
corresponding update for Ubuntu 18.04 LTS and Ubuntu 18.10.

Original advisory details:

 Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings. A
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

  script_tag(name:"affected", value:"'freerdp' package(s) on Ubuntu 18.04, Ubuntu 18.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.10.1", rls:"UBUNTU18.10"))) {
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
