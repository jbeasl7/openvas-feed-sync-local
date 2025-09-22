# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66483");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-1250", "CVE-2009-1251");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:099-1 (openafs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in openafs:

The cache manager in the client in OpenAFS 1.0 through 1.4.8 and
1.5.0 through 1.5.58 on Linux allows remote attackers to cause a
denial of service (system crash) via an RX response with a large
error-code value that is interpreted as a pointer and dereferenced,
related to use of the ERR_PTR macro (CVE-2009-1250).

Heap-based buffer overflow in the cache manager in the client in
OpenAFS 1.0 through 1.4.8 and 1.5.0 through 1.5.58 on Unix platforms
allows remote attackers to cause a denial of service (system crash)
or possibly execute arbitrary code via an RX response containing
more data than specified in a request, related to use of XDR arrays
(CVE-2009-1251).

The updated packages have been patched to correct these issues.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:099-1");
  script_tag(name:"summary", value:"The remote host is missing an update to openafs
announced via advisory MDVSA-2009:099-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libopenafs1-devel", rpm:"libopenafs1-devel~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64openafs1-devel", rpm:"lib64openafs1-devel~1.4.4~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
