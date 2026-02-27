# KS<span style="color: red">e</span>F **XML** Download

<a href="https://github.com/sstybel/ksef-xml-download/releases/latest"><img alt="Static Badge" src="https://img.shields.io/badge/download-red?style=for-the-badge&label=stable&color=%23FF0000&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download%2Freleases%2Flatest"></a> ![GitHub Release](https://img.shields.io/github/v/release/sstybel/ksef-xml-download?sort=date&display_name=release&style=for-the-badge&logo=github&label=release&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download) ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/sstybel/ksef-xml-download/total?style=for-the-badge&logo=github&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download)

A tool for downloading invoices in **XML** format from the National e-Invoice System ([**KS<span style="color: red">e</span>F** - **K**rajowy **S**ystem **<span style="color: red">e</span>-F**aktur](https://ksef.podatki.gov.pl/)) - https://ksef.podatki.gov.pl/.

The repository of this tool is based on a fork originating from:
1. https://github.com/Pafkaja/ksef_faktury_list ([**@Pafkaja (PaFka)**](https://github.com/Pafkaja))
2. https://github.com/CIRFMF/ksef-pdf-generator ([**@CIRF**](https://github.com/CIRFMF))

The application can list and download in **XML** format a set of available purchase invoices (received) as well as sales invoices (issued) in the **KSeF** system. In the application, you can specify the time interval within which invoices will be downloaded from the **KSeF** system. 

Additionally, a status file (`ksef_state.json`) of downloaded documents (invoices) can be generated to avoid redundant downloading of documents that have already been downloaded. 

The software can also download purchase (*Subject2*) and sales invoices (*Subject2*) with their storage locations separated into different locations (folders). In addition, the result file is generated in one of three formats (**JSON**, **TXT**, and **CSV**). 

The output file in **JSON** format can be used by the [**KSeF PDF Generator**](https://github.com/sstybel/ksef-pdf-generator) tool to generate a visualization of invoices in **PDF** format, based on invoices downloaded in **XML** format from the **KSeF** system. This solution simplifies the process of converting invoices to **PDF** format, as the output file contains the location of the **XML** invoice files. 

Be sure to check out and download this tool as well: [**KSeF PDF Generator**](https://github.com/sstybel/ksef-pdf-generator)

&nbsp;

![Example Screen-Shot ](https://github.com/sstybel/ksef-xml-download/blob/main/images/screen01.png)

## Syntax of the `ksef-xml-download.exe`

**Usage:** `ksef-xml-download.exe` `--nip NIP` [`--cert CERT`] [`--key KEY`] [`--password PASSWORD`] [`--password-file PASSWORD_FILE`] [`--token TOKEN`] [`--token-file TOKEN_FILE`] [`--env {prod | test | demo}`] [`--date-from DATE_FROM`] [`--date-to DATE_TO`] [`--subject-type {Subject1 | Subject2 | Subject1and2}`] [`--ksef-state-dir KSEF_STATE_DIR`] [`--output {json | csv | table}`] [`--output-dir OUTPUT_DIR`] [`--download-xml`] [`--xml-output-dir XML_OUTPUT_DIR`] [`--xml-sub1-output-dir XML_SUB1_OUTPUT_DIR`] [`--xml-sub2-output-dir XML_SUB2_OUTPUT_DIR`] [`--verbose`] [`--help`]

**Options:**
*  `--nip NIP` - **NIP** (Tax ID) of the entity (required for **KSeF** queries)
* `--env {prod | test | demo}` - **KSeF** environment (default: `prod`)
* `--date-from DATE_FROM` - Start date YYYY-MM-DD (default: 30 days ago)
* `--date-to DATE_TO` - End date YYYY-MM-DD (default: today)
* `--subject-type {Subject1 | Subject2 | Subject1and2}`
Subject1 => issued/sales, Subject2 => received/purchases, Subject1and2 => issued/sales and received/purchases (default subject type: `Subject2`)
* `--ksef-state-dir KSEF_STATE_DIR` - Path to the state file (ksef_state.json) for downloading invoices from the **KSeF** system. If not provided, the state will be stored in the current directory.
* `--output {json | csv | table}` - Output format of results to display and save to file under the name according to the pattern `ksef_invoices-output-[json | csv | txt]_YYYYMMDDhhmmss.[json | csv | txt]` (default output format: `json`)
* `--output-dir OUTPUT_DIR` - Directory to save output files (default: current directory)
* `--download-xml` - Download full KSeF **XML** for each invoice
* `--xml-output-dir XML_OUTPUT_DIR` - Directory to save KSeF **XML** files for all types of invoice (issued/sales or/and received/purchases) (default: current directory)
* `--xml-sub1-output-dir XML_SUB1_OUTPUT_DIR` - Directory to save KSeF **XML** files for **Subject1 - issued/sales** (default: current directory)
* `--xml-sub2-output-dir XML_SUB2_OUTPUT_DIR` - Directory to save KSeF **XML** files for **Subject2 - received/purchases** (default: current directory)
* `--verbose`, `-v` - Enable verbose logging
* `--help`, `-h` - Show this help message and exit

**Certificate authentication (XAdES):**
* `--cert CERT` - Path to certificate file (**PEM**)
* `--key KEY` - Path to private key file (**PEM**)
* `--password PASSWORD` - Password for encrypted private key
* `--password-file PASSWORD_FILE` - File containing password for private key

**Token authentication:**
* `--token TOKEN` - **KSeF** authorization token
* `--token-file TOKEN_FILE` - File containing **KSeF** token

## Examples

<br>

> Certificate authentication (XAdES) to **KSeF** system - requires **NIP** (Tax ID), cert, key, and password

```sh
ksef-xml-download.exe --nip 1234567890 --cert cert.pem --key key.pem --password secret

ksef-xml-download.exe --nip 1234567890 --cert cert.pem --key key.pem --password-file pass.txt
```
> Token authentication to **KSeF** system - requires **NIP** (Tax ID), token

```sh
ksef-xml-download.exe --nip 1234567890 --token "your-ksef-token"

ksef-xml-download.exe --nip 1234567890 --token-file token.txt
```

> With options

```sh
ksef-xml-download.exe --nip 1234567890 --token-file token.txt --env prod --date-from 2026-02-01

ksef-xml-download.exe --nip 1234567890 --token-file token.txt --env prod --subject-type Subject1
                      --output json --xml-output-dir .\invoices-sales\

ksef-xml-download.exe --nip 1234567890 --token-file token.txt
                      --env prod --ksef-state-dir d:\_test-ksef_\state\
                      --subject-type Subject1and2 --output json
                      --output-dir d:\_test-ksef_\output\
                      --download-xml
                      --xml-output-dir d:\_test-ksef_\invoices\
```

&nbsp;

![Example Screen-Shot ](https://github.com/sstybel/ksef-xml-download/blob/main/images/screen01.png)

## Download

<a href="https://github.com/sstybel/ksef-xml-download/releases/latest"><img alt="Static Badge" src="https://img.shields.io/badge/download-red?style=for-the-badge&label=stable&color=%23FF0000&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download%2Freleases%2Flatest"></a> ![GitHub Release](https://img.shields.io/github/v/release/sstybel/ksef-xml-download?sort=date&display_name=release&style=for-the-badge&logo=github&label=release&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download) ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/sstybel/ksef-xml-download/total?style=for-the-badge&logo=github&link=https%3A%2F%2Fgithub.com%2Fsstybel%2Fksef-xml-download)

##  GitHub

![GitHub stats](https://github-readme-stats-sigma-five.vercel.app/api?username=sstybel&show_icons=true&theme=react&hide_title=true&include_all_commits=true)

&nbsp;

---

## Copyright &copy; 2025 - 2026 by Sebastian Stybel, [www.BONO-IT.pl](https://www.bono-it.pl/)
