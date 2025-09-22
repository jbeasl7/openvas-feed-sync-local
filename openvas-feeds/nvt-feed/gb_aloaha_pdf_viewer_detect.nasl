# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804311");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-02-12 20:03:19 +0530 (Wed, 12 Feb 2014)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Aloaha PDF Suite PDF Viewer Detection (Windows SMB Login)");


  script_tag(name:"summary", value:"Detects the installed version of Aloaha PDF Suite PDF Viewer on Windows.

The script logs in via smb, searches for Aloaha PDF Suite in the registry
and gets the pdf viewer path from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

key = "SOFTWARE\Aloaha";
if(!registry_key_exists(key:key)){
  exit(0);
}

pdfPath = registry_get_sz(key:"SOFTWARE\Aloaha\pdf", item:"Path");
pdfPath = pdfPath + "\PDFViewer" ;

if(pdfPath)
{
  pdfVer = fetch_file_version(sysPath: pdfPath, file_name:"AloahaPDFViewer.exe");
  if(!pdfVer)
    exit(0);

  set_kb_item(name:"Aloaha/PDF/Viewer", value:pdfVer);

  cpe = build_cpe(value:pdfVer, exp:"^([0-9.]+)", base:"cpe:/a:aloha:aloahapdfviewer:");
  if(isnull(cpe))
    cpe = "cpe:/a:aloha:aloahapdfviewer";

  register_product(cpe: cpe, location: pdfPath);

  log_message(data: build_detection_report(app: "Aloaha PDF Viewer",
                                          version: pdfVer,
                                          install: pdfPath,
                                          cpe: cpe,
                                          concluded: pdfVer));
}
