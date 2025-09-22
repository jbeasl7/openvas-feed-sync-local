# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0351");
  script_cve_id("CVE-2024-49767");
  script_tag(name:"creation_date", value:"2024-11-11 04:11:21 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 20:03:04 +0000 (Tue, 05 Nov 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0351)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0351");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0351.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33732");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7093-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-werkzeug' package(s) announced via the MGASA-2024-0351 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Werkzeug is a Web Server Gateway Interface web application library.
Applications using `werkzeug.formparser.MultiPartParser` corresponding
to a version of Werkzeug prior to 3.0.6 to parsing `multipart/form-data`
requests (e.g. all flask applications) are vulnerable to a relatively
simple but effective resource exhaustion (denial of service) attack. A
specifically crafted form submission request can cause the parser to
allocate and block 3 to 8 times the upload size in main memory. There is
no upper limit, a single upload at 1 Gbit/s can exhaust 32 GB of RAM in
less than 60 seconds. Werkzeug version 3.0.6 fixes this issue.");

  script_tag(name:"affected", value:"'python-werkzeug' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-werkzeug", rpm:"python-werkzeug~3.0.6~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-werkzeug", rpm:"python3-werkzeug~3.0.6~1.mga9", rls:"MAGEIA9"))) {
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
